LABEL = "oldest-taint candidate (br_x twin hit)"


def matches(kind, twin_hit) -> bool:
    return kind == "br_x" and bool(twin_hit)


def confirmed(evidence) -> bool:
    return bool(evidence and evidence.get("oldest_taint_signature"))
