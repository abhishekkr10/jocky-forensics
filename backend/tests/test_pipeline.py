import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path

from backend.app.core import ROOT, native
from backend.app.engine import run, report_html
from backend.app import integrity
from backend.app.detection import compile_sigma, Unsupported
import pytest

@pytest.fixture(scope="module")
def bundle(): return run((ROOT/"examples/triage.jky").read_text(),"fixture","fixture")

def test_real_engines_and_trace(bundle):
    assert {d["engine"] for d in bundle["detections"]} == {"Sigma","YARA-X"}
    assert bundle["verification"]["integrity"] == "valid"
    assert all(e["record"]["provenance_kind"]=="synthetic" for s in bundle["streams"] for e in s["entries"])
    assert all(e["record"]["source_span"]["line"]>0 for s in bundle["streams"] for e in s["entries"])
    assert bundle["analysis"]["risk"]["label"]=="LAB RISK SCORE"
    assert "Evidence" in report_html(bundle)

@pytest.mark.parametrize("change",["record","middle","tail","order","blob","checkpoint","head","stream","key"])
def test_tampering(bundle,change):
    b=copy.deepcopy(bundle);s=b["streams"][0]
    if change=="record":s["entries"][0]["record"]["payload"]["os"]="altered"
    elif change=="middle":s["entries"].pop(1)
    elif change=="tail":s["entries"].pop()
    elif change=="order":s["entries"][0],s["entries"][1]=s["entries"][1],s["entries"][0]
    elif change=="blob":b["blobs"][next(iter(b["blobs"]))]="00"
    elif change=="checkpoint":b["checkpoint"]["manifest"]["plan_digest"]="altered"
    elif change=="head":s["chain_head"]="0"*64
    elif change=="stream":b["streams"]=[]
    else:b["checkpoint"]["public_key"]="0"*64
    assert integrity.verify(b)["integrity"]=="invalid"
    assert integrity.verify(bundle)["integrity"]=="valid"

def test_reproducibility(bundle):
    b=run((ROOT/"examples/triage.jky").read_text(),"fixture","fixture")
    assert b["streams"]==bundle["streams"]
    assert b["analysis"]==bundle["analysis"]

def test_sigma_unsupported():
    with pytest.raises(Unsupported):compile_sigma("title: Test\nlogsource: {category: process_creation}\ndetection:\n  s:\n    Image|re: '.*'\n  condition: s\n")

@pytest.mark.parametrize("condition,expected",[("a and not b",[True,False]),("1 of them",[True,True]),("all of them",[False,True]),("(a or b) and a",[True,True])])
def test_sigma_boolean(condition,expected):
    _,p=compile_sigma(f"title: Test\nlogsource: {{category: process_creation}}\ndetection:\n  a:\n    Image: cmd.exe\n  b:\n    User: admin\n  condition: {condition}\n")
    assert native("predicate",{"predicate":p,"events":[{"Image":"cmd.exe","User":"user"},{"Image":"cmd.exe","User":"admin"}]})["matches"]==expected

def test_report_escapes(bundle):
    b=copy.deepcopy(bundle);b["source"]="<script>alert(1)</script>"
    assert "<script>alert(1)</script>" not in report_html(b)

def test_live_system():
    b=run("mode live\ntarget host\ncollect system_information as s\nverify evidence","live","live")
    assert b["streams"][0]["entries"][0]["record"]["provenance_kind"]=="live"
    assert integrity.verify(b)["integrity"]=="valid"
