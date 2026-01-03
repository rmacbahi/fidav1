import orjson


def canonical_json_bytes(obj: object) -> bytes:
    # Deterministic JSON for hashing. Not full RFC8785 edge-cases, but stable:
    # - sorted keys
    # - UTF-8
    # - no whitespace
    # For true RFC8785, replace with a strict canonicalizer once you lock spec.
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS)
