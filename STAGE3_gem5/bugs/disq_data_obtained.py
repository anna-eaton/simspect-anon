LABEL = "disq_not_obtained"


def label(raw):
    if raw.get("data_obtained") is False:
        return f"disq_not_obtained({raw.get('cache_fate')})"
    return None
