from ._trace import cs_actor, cs_is_victim_item, cs_split_seqs, cs_victim_chain

LABEL = "CS1"
CAUSE = "CS1_older_store_upgrade"


def judge(item, tr):
    es, S, _ = cs_actor(item, tr)
    if es is None or not cs_is_victim_item(item, es, S) or S in cs_split_seqs(tr[0]):
        return None
    c = cs_victim_chain(item, es, S, tr)
    if c["ok"] and c["U"] is not None and c["U"] < c["Q"] and c["U"] in tr[2]:
        return c["chain"]
    return None
