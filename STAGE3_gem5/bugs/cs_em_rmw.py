LABEL = "EM_rmw"


def matches(pc, xpc, rmw) -> bool:
    return pc == xpc and bool(rmw)
