LABEL = "walk_order"


def load_tag(L):
    return "walk_order" if L["first"]["prevnounsafe"] == 1 else None


def in_tags(tags) -> bool:
    return "walk_order" in tags or any("walk_order" in t for t in tags)
