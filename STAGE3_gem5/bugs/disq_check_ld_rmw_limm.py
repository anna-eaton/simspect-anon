LABEL = "check_ld RMW artifact (scores the RMW's leading limm micro-op; delay unit holds the load)"


def matches(rp, e) -> bool:
    return rp == "rmw" and e is not None and "isTainted=1 isSpeculative=1" in (e.get("stl") or "") and not e.get("fwd")
