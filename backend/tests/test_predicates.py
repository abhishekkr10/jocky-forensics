from backend.app.predicates import matches
from backend.app.engine import run

def test_typed_and_missing_comparisons():
    assert matches({"field":"pid","op":">=","value":100},{"pid":4242})
    assert not matches({"field":"pid","op":">=","value":100},{"pid":"4242"})
    assert not matches({"field":"missing","op":"!=","value":1},{})
    assert matches({"field":"flag","op":"==","value":True},{"flag":True})
    assert not matches({"field":"flag","op":"==","value":True},{"flag":1})

def test_compound_filter_in_real_pipeline():
    bundle=run('mode lab\ncollect processes as p\nfilter p where pid >= 100 and (name == "powershell.exe" or name == "cmd.exe") as f\nassert f where not name startswith "cmd"\nexport f json "selected.json"\nverify evidence',"compound","compound-case")
    assert len(next(iter(bundle["exports"].values())))==1
