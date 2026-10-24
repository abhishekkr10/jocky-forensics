from backend.app.engine import run
from backend.app.core import native

def test_function_calls_preserve_distinct_outputs_and_source_trace():
    source='''function select(input)
filter input where pid > 100 as result
return result
end
mode lab
collect processes as p
call select(p) as first
call select(p) as second
assert first where pid == 4242
assert second where pid == 4242
verify evidence
'''
    bundle=run(source,"functions","functions-case")
    assert bundle['verification']['integrity']=='valid'
    assert bundle['plan']['source_map']['op002']['line']==7
    assert bundle['plan']['nodes'][2]['output']=='second'

def test_rejects_recursive_and_undefined_function_calls():
    for source in ['call missing(p) as x','function f(p)\ncall f(p) as x\nreturn x\nend']:
        assert not native('compile',{'source':source})['ok']
