import hashlib
import json
import time
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .core import DATA, native

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()

def signing_key():
    path = DATA / "checkpoint.key"
    if not path.exists():
        key = Ed25519PrivateKey.generate()
        try:
            with path.open("xb") as out:
                out.write(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            path.chmod(0o600)
        except FileExistsError:
            pass
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())

def public_key():
    return signing_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

def signed_job(plan_digest, operation_id, approved_root, execution_id):
    body={"version":"1.0","plan_digest":plan_digest,"operation_id":operation_id,"approved_root":approved_root,
          "execution_id":execution_id,"issued_at":int(time.time()),"expires_at":int(time.time())+60,"nonce":secrets.token_hex(16)}
    return {"body":body,"signature":signing_key().sign(canonical(body)).hex()}

def analysis_digest(bundle):
    return hashlib.sha256(canonical({k:bundle[k] for k in ("source","plan","detections","coverage","operations","analysis","exports")})).hexdigest()

def checkpoint(streams, plan_digest, result_digest):
    manifest = {"version": "1.0", "plan_digest": plan_digest, "analysis_digest":result_digest,"streams": [
        {"stream_id": s["stream_id"], "record_count": s["record_count"], "chain_head": s["chain_head"], "completeness": s["completeness"]} for s in streams]}
    return {"manifest": manifest, "signature": signing_key().sign(canonical(manifest)).hex(), "public_key": public_key()}

def verify(bundle, trusted_key=None):
    try:
        cp = bundle["checkpoint"]
        key = trusted_key or public_key()
        if cp["public_key"] != key:
            raise ValueError("Checkpoint signer differs from trusted key")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(cp["signature"]), canonical(cp["manifest"]))
        if cp["manifest"]["plan_digest"] != bundle["plan_digest"]:
            raise ValueError("Plan digest differs from checkpoint")
        if cp["manifest"]["analysis_digest"] != analysis_digest(bundle):
            raise ValueError("Analysis or source changed after checkpoint")
        expected = cp["manifest"]["streams"]
        streams = bundle["streams"]
        if len(expected) != len(streams) or len({s["stream_id"] for s in streams}) != len(streams):
            raise ValueError("Missing or duplicate expected endpoint stream")
        for target, stream in zip(expected, streams):
            for key in ("stream_id", "record_count", "chain_head", "completeness"):
                if target[key] != stream[key]:
                    raise ValueError(f"Checkpoint {key} mismatch")
            result = native("verify", stream)
            if result["integrity"] != "valid":
                raise ValueError(result["error"])
            for entry in stream["entries"]:
                ref = entry["record"].get("raw_reference") or {}
                digest = ref.get("blob_sha256")
                if digest and hashlib.sha256(bytes.fromhex(bundle["blobs"][digest])).hexdigest() != digest:
                    raise ValueError("Raw blob digest mismatch")
        return {"integrity": "valid", "completeness": "complete" if all(s["completeness"] == "complete" for s in streams) else "partial", "anchor": "server signing key; export checkpoint independently"}
    except Exception as exc:
        return {"integrity": "invalid", "completeness": "unknown", "error": str(exc) or type(exc).__name__}
