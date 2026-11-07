def build(nodes: list[dict], relationships: list[dict]) -> dict:
    identifiers = {node["id"] for node in nodes}
    for relationship in relationships:
        if relationship["source"] not in identifiers or relationship["target"] not in identifiers:
            raise ValueError("Attack-surface relationship references an unknown node")
        if not 0 <= relationship["confidence"] <= 1:
            raise ValueError("Invalid graph relationship confidence")
    return {"schema_version": "1.0", "nodes": nodes,
            "observed_edges": [item for item in relationships if not item["inferred"]],
            "inferred_edges": [item for item in relationships if item["inferred"]]}
