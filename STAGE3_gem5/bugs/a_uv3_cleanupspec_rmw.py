LABEL = "UV3"


def matches(pc, xpc, rmw) -> bool:
    return pc == xpc and bool(rmw)
