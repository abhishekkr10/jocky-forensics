"""Case-sensitive, typed JOCKY dataset comparisons; no expression execution."""
def matches(predicate,payload):
    op=predicate["op"]
    if op=="and": return all(matches(p,payload) for p in predicate["args"])
    if op=="or": return any(matches(p,payload) for p in predicate["args"])
    if op=="not": return not matches(predicate["arg"],payload)
    current=payload
    for part in predicate["field"].split("."):
        if not isinstance(current,dict) or part not in current: return False
        current=current[part]
    expected=predicate["value"]
    if op in {">",">=","<","<="}:
        if type(current) not in {int,float} or type(expected) not in {int,float}: return False
        return {">":lambda:current>expected,">=":lambda:current>=expected,"<":lambda:current<expected,"<=":lambda:current<=expected}[op]()
    if op in {"==","!="}:
        # Retain legacy text comparison for untyped string literals.
        equal=str(current)==expected if isinstance(expected,str) and current is not None else type(current)==type(expected) and current==expected
        return equal if op=="==" else not equal
    if not isinstance(current,str) or not isinstance(expected,str): return False
    if op=="contains": return expected in current
    if op=="startswith": return current.startswith(expected)
    if op=="endswith": return current.endswith(expected)
    raise ValueError("Unsupported dataset comparison")
