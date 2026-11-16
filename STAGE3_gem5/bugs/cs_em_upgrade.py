from ._trace import cs_actor, cs_is_victim_item, cs_is_install_item, cs_split_seqs, cs_victim_chain, cs_sel

LABEL = "EM_upgrade"
CAUSE = "EM_upgrade_squashed"


def judge(item, tr):
    es, S, _ = cs_actor(item, tr)
    if es is None:
        return None
    evs, by_id, committed = tr
    line = item["line"]
    if cs_is_victim_item(item, es, S):
        if S in cs_split_seqs(evs):
            return None
        c = cs_victim_chain(item, es, S, tr)
        if c["ok"] and c["U"] is not None and c["U"] not in committed and c["U"] > c["Q"]:
            return c["chain"]
        return None
    if cs_is_install_item(item, es, S):
        if any(e["seqn"] == S and e.get("line") == line for e in cs_sel(evs, "L1D", "cleanup_skip", why="split")):
            return None
        e0 = es[0]
        sk = [e for e in cs_sel(evs, "L1D", "cleanup_skip", line=line, seq=str(S))
              if e.get("ev") == "Inv_CLEANUP" and e.get("st") == "M"]
        ups = [e for e in cs_sel(evs, "L1D", "hit", line=line, st="E", nst="M") if sk and e0["tick"] <= e["tick"] <= sk[0]["tick"]]
        if len(sk) == 1 and len(ups) == 1 and ups[0]["seqn"] not in committed:
            return f"S={S} fill {line}; squashed U={ups[0]['seqn']} st E->M @{ups[0]['tick']}; cleanup_skip st=M @{sk[0]['tick']}"
    return None
