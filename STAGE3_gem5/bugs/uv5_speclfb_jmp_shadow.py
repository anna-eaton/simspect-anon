LABEL = "jmp_shadow"


def load_tag(L):
    if "direct_jmp_call_in_shadow" in L["why_safe"]:
        return "jmp_shadow" + ("+walk_order" if "prevnounsafe" in L["why_safe"] else "")
    return None


def in_tags(tags) -> bool:
    return any(t.startswith("jmp_shadow") for t in tags)
