LABEL = "SSE-load producer"


def gate_class(sl) -> str:
    return ("SSE-load producer (static)" if sl.get("sse_producer")
            else "other(xmm on slice)" if sl.get("xmms") else "other(GPR slice)")


def is_static(cl) -> bool:
    return cl.startswith("SSE-load producer")


def untainted(e) -> bool:
    return e is not None and "isTainted=0" in (e.get("stl") or "")
