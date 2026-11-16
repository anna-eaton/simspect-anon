from ._trace import cs_actor, cs_is_victim_item, cs_is_install_item, cs_split_seqs, cs_sel

LABEL = "UV4"
CAUSE = "UV4_split"


def judge(item, tr):
    es, S, _ = cs_actor(item, tr)
    if es is None:
        return None
    evs = tr[0]
    line = item["line"]
    if cs_is_victim_item(item, es, S):
        if S in cs_split_seqs(evs):
            return f"S={S} filled {es[0].get('line')} evicting V={line}; cleanup_skip seq={S} why=split"
        return None
    if cs_is_install_item(item, es, S):
        if any(e["seqn"] == S and e.get("line") == line for e in cs_sel(evs, "L1D", "cleanup_skip", why="split")):
            return f"S={S} fill {item['struct']} {line}; cleanup_skip line={line} seq={S} why=split"
    return None
