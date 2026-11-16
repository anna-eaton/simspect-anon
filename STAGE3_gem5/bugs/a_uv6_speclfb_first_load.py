LABEL = "UV6"


def load_tag(L):
    return "uv6_first" if L["rank"] == 0 else None


def in_tags(tags) -> bool:
    return "uv6_first" in tags
