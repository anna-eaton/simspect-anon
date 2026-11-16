from ._trace import cs_actor, cs_sel

LABEL = "UV5"
CAUSE = "UV5_older_load"


def judge(item, tr):
    es, S, _ = cs_actor(item, tr)
    if es is None or item["term"] != "over_clean":
        return None
    evs, by_id, committed = tr
    line = item["line"]
    fills = [e for e in es if e["kind"] == "fill" and e.get("line") == line and e["seqn"] == S]
    invs = cs_sel(evs, "L1D", "cleanup_inv", line=line, seq=str(S))
    if fills and invs:
        hits = [e for e in cs_sel(evs, "L1D", "hit", line=line)
                if fills[0]["tick"] <= e["tick"] <= invs[0]["tick"] and e["seqn"] is not None
                and e["seqn"] < S and e["seqn"] in committed]
        if hits:
            h = hits[0]
            return (f"S={S} fill {line} @{fills[0]['tick']}; older committed U={h['seqn']} "
                    f"req={h.get('req')} addr={h.get('addr')} size={h.get('size')} hits @{h['tick']}; "
                    f"cleanup_inv @{invs[0]['tick']}")
    return None
