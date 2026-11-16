LABEL = "UV1_transient"


def is_transient(e, vp) -> bool:
    v = vp.get(str(e.get("seq")))
    return isinstance(v, list) and bool(v) and v[0] == float("inf")
