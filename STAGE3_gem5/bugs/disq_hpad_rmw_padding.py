LABEL = "UV3_padding|EM_padding"


def is_padding(pc: int, xpc, dis_by_pc) -> bool:
    return xpc is not None and pc > xpc and dis_by_pc.get(pc) == "ADD_M_R"
