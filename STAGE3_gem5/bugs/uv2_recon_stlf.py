LABEL = "STLF bypass"


def matches(e) -> bool:
    return (e is not None and e.get("reproduced", True) and "isTainted=1 isSpeculative=1" in (e.get("stl") or "")
            and bool(e.get("fwd")) and bool(e.get("ready_in_window")))
