LABEL = "UV1"


def is_event(e) -> bool:
    return bool(e) and e["struct"] == "L1D" and e["kind"] == "evict" and e.get("req") == "specld"
