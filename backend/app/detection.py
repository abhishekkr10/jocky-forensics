"""pySigma condition lowering and real YARA-X scanning of captured bytes."""
import hashlib
import importlib.metadata
import yaml
import yara_x
from sigma.rule import SigmaRule
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaString, SigmaNumber, SigmaBool, SigmaNull, SpecialChars
from .core import ROOT, native

class Unsupported(ValueError):
    pass

def lower(node):
    if isinstance(node, (ConditionAND, ConditionOR)):
        return {"op": "and" if isinstance(node, ConditionAND) else "or", "args": [lower(x) for x in node.args]}
    if isinstance(node, ConditionNOT):
        return {"op": "not", "arg": lower(node.args[0])}
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        raise Unsupported(f"Unsupported condition: {type(node).__name__}")
    value = node.value
    if isinstance(value, SigmaString):
        parts = list(value.s)
        if any(isinstance(x, str) and ("*" in x or "?" in x) for x in parts):
            raise Unsupported("Escaped literal wildcard is not supported by this evaluator")
        text = "".join("*" if x == SpecialChars.WILDCARD_MULTI else "?" if x == SpecialChars.WILDCARD_SINGLE else str(x) for x in parts)
        return {"op": "wildcard" if value.contains_special() else "eq", "field": node.field, "value": text}
    if isinstance(value, SigmaNull):
        value = None
    elif isinstance(value, (SigmaNumber, SigmaBool)):
        value = value.value
    else:
        raise Unsupported(f"Unsupported value: {type(value).__name__}")
    return {"op": "eq", "field": node.field, "value": value}

def compile_sigma(text):
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or "correlation" in document:
        raise Unsupported("Only event rules are supported")
    for name, selection in document.get("detection", {}).items():
        if name == "condition":
            continue
        if not isinstance(selection, dict):
            raise Unsupported("Only field-based selections are supported")
        for field in selection:
            if any(m not in {"contains", "startswith", "endswith", "all"} for m in field.split("|")[1:]):
                raise Unsupported(f"Unsupported modifier in {field}")
    rule = SigmaRule.from_yaml(text)
    conditions = [lower(c.parsed) for c in rule.detection.parsed_condition]
    return rule, conditions[0] if len(conditions) == 1 else {"op": "or", "args": conditions}

def sigma(records, operation_id):
    text = (ROOT / "rules/sigma/encoded_script.yml").read_text()
    pack_digest = hashlib.sha256(text.encode()).hexdigest()
    try:
        rule, predicate = compile_sigma(text)
    except Unsupported as exc:
        return [], {"engine": "Sigma", "state": "unsupported", "reason": str(exc)}
    eligible = [r for r in records if r["event_kind"] == "process_creation" and r["payload"].get("product") == "windows"]
    if not eligible:
        return [], {"engine": "Sigma", "state": "insufficient_telemetry", "pack_digest": pack_digest}
    matches = native("predicate", {"predicate": predicate, "events": [r["payload"] for r in eligible]})["matches"]
    hits = [{"id": f"sigma-{operation_id}-{i}", "engine": "Sigma", "rule": rule.title, "rule_id": str(rule.id),
             "severity": "medium", "evidence_ids": [r["evidence_id"]], "operation_id": operation_id,
             "pack_digest": pack_digest, "engine_version": importlib.metadata.version("pysigma"),
             "provenance_kind": r["provenance_kind"], "reason": "Image ends with powershell.exe and command line contains EncodedCommand"}
            for i, (r, match) in enumerate(zip(eligible, matches)) if match]
    return hits, {"engine": "Sigma", "state": "matched" if hits else "evaluated_no_match", "evaluated": len(eligible), "excluded": len(records)-len(eligible), "pack_digest": pack_digest}

def yara(records, operation_id, blobs):
    text = (ROOT / "rules/yara/demo.yar").read_text()
    rules = yara_x.compile(text)
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(5)
    hits = []
    for record in records:
        digest = record.get("raw_reference", {}).get("blob_sha256")
        if not digest or digest not in blobs:
            continue
        content = bytes.fromhex(blobs[digest])
        if len(content) > 1048576 or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("Invalid captured scan bytes")
        for match in scanner.scan(content).matching_rules:
            offsets = []
            for pattern in match.patterns:
                for m in pattern.matches:
                    offsets.append({"offset": m.offset, "length": m.length})
            hits.append({"id": f"yara-{operation_id}-{len(hits)}", "engine": "YARA-X", "rule": match.identifier,
                         "namespace": match.namespace, "severity": "low", "evidence_ids": [record["evidence_id"]],
                         "operation_id": operation_id, "scanned_sha256": digest, "offsets": offsets,
                         "pack_digest": hashlib.sha256(text.encode()).hexdigest(), "engine_version": importlib.metadata.version("yara-x"),
                         "provenance_kind": record["provenance_kind"], "reason": "Harmless demonstration marker found in captured file bytes"})
    return hits, {"engine": "YARA-X", "state": "matched" if hits else "evaluated_no_match", "evaluated": len(records)}
