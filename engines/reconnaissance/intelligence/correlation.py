from ..database.store import Store


def correlate(identifier: str, mode: str, relationships: list, store: Store) -> None:
    by_name = {}
    for asset in store.assets(identifier):
        by_name.setdefault(asset["name"], []).append(asset["id"])
    for relationship in relationships:
        source = by_name.get(relationship.source, [])
        target = by_name.get(relationship.target, [])
        if len(source) != 1 or len(target) != 1:
            raise ValueError("Relationship references missing or ambiguous assets")
        evidence = store.capture(identifier, relationship.source_reference, mode, relationship.model_dump())
        store.edge(identifier, source[0], target[0], relationship.relation, evidence,
                   True, min(relationship.confidence, 0.7))
    store.event(identifier, "correlation", "Observed and inferred relationships stored separately")


def http_intelligence(identifier: str, observation: dict, reference: str, store: Store) -> None:
    if not 200 <= observation["status"] < 300:
        return
    url = observation["url"]
    app = store.asset(identifier, "application", url, reference, {"http_status": observation["status"]})
    keys = observation.get("json_keys", [])
    if observation["path"] == "/openapi.json" and "api_paths" in observation:
        api = store.asset(identifier, "api", url, reference, {"paths": observation.get("api_paths", [])})
        store.edge(identifier, app, api, "exposes", reference, False, 1)
    if "models" in observation:
        engine = "Ollama-compatible" if observation["path"] == "/api/tags" else "OpenAI-compatible"
        server = store.asset(identifier, "model_server", url, reference, {"interface": engine}, inferred=True, confidence=0.8)
        for model in observation["models"]:
            node = store.asset(identifier, "model", model, reference, {"basis": "advertised_model_id_not_verified_weights"}, inferred=True, confidence=0.7)
            store.edge(identifier, server, node, "exposes", reference, True, 0.7)
    if "agent_name" in observation and "skills" in keys:
        node = store.asset(identifier, "a2a_service", url, reference, {"advertised_name": observation["agent_name"]}, inferred=True, confidence=0.8)
        store.edge(identifier, app, node, "exposes", reference, True, 0.8)
    controls = {key: value for key, value in observation["headers"].items() if key in {
        "content-security-policy", "x-content-type-options", "strict-transport-security", "www-authenticate"}}
    if controls:
        store.asset(identifier, "security_control", url + "#headers", reference, controls,
                    inferred=True, confidence=0.6)
