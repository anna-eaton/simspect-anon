

def _over_keys(raw):
    out_w = {(r.get("struct"), r.get("line")) for r in raw.get("over_clean_outside_window") or []}
    return {(r["struct"], r["line"]) for r in raw.get("per_line") or []
            if (r.get("d_install", 0) < 0 or r.get("d_victim", 0) < 0)} - out_w


def normalize(raw):
    ns = raw.get("net_state")
    if not isinstance(ns, dict) or "inconsistent" not in raw or not ns.get("outside_window"):
        return raw, False
    over = _over_keys(raw)
    move = [r for r in ns["outside_window"] if (r["struct"], r["line"]) in over]
    if not move:
        return raw, False
    differing = list(ns.get("differing") or []) + move
    outside = [r for r in ns["outside_window"] if (r["struct"], r["line"]) not in over]
    count_keys = {(o["struct"], o["line"]) for o in raw.get("offending") or []}
    net_keys = {(r["struct"], r["line"]) for r in differing}
    inconsistent = net_keys != count_keys
    count_leak = bool(raw.get("offending"))
    net = bool(differing)
    new = dict(raw, net_state=dict(ns, leak=net, differing=differing, outside_window=outside),
               inconsistent=inconsistent, decided=not inconsistent)
    iiw = (count_leak or net) if inconsistent else count_leak
    assert iiw == bool(raw.get("issued_in_window")), f"over_clean exemption would change issued_in_window of {raw.get('name')}"
    return new, (inconsistent != raw.get("inconsistent"))
