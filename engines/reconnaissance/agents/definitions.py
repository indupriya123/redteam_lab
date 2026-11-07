from ..skills.registry import Registry

NAMES = [
    "External Attack Surface Agent", "Network Discovery Agent", "DNS Intelligence Agent",
    "Port Discovery Agent", "Service Fingerprinting Agent", "Web Technology Discovery Agent",
    "API Discovery Agent", "AI Application Discovery Agent", "LLM Model Fingerprinting Agent",
    "AI Framework Discovery Agent", "RAG Architecture Discovery Agent", "Embedding Discovery Agent",
    "Vector Database Discovery Agent", "AI Agent Discovery Agent", "MCP Discovery Agent",
    "A2A Discovery Agent", "AI Supply Chain Discovery Agent", "Cloud Reconnaissance Agent",
    "Kubernetes and Container Discovery Agent", "AI Identity and Authentication Discovery Agent",
    "AI Security Control Discovery Agent", "Telemetry and Monitoring Discovery Agent",
    "Reconnaissance Correlation Agent",
]
SKILLS = [
    "external_attack_surface", "network_discovery", "dns_intelligence", "full_port_discovery",
    "service_fingerprinting", "web_fingerprinting", "api_discovery", "ai_application_discovery",
    "llm_fingerprinting", "ai_framework_discovery", "rag_discovery", "embedding_discovery",
    "vector_database_discovery", "agent_discovery", "mcp_discovery", "a2a_discovery",
    "ai_supply_chain", "cloud_discovery", "kubernetes_discovery", "identity_discovery",
    "defensive_control_discovery", "telemetry_discovery",
]


def definitions(registry: Registry) -> list[dict]:
    skills = {skill["id"]: skill for skill in registry.describe()}
    if len(skills) != 22:
        raise ValueError("Reconnaissance requires exactly 22 approved skill definitions")
    result = []
    for name, skill_id in zip(NAMES, SKILLS):
        skill = skills[skill_id]
        result.append({"name": name, "id": skill["agent"], "skills": [skill["id"]],
                       "inputs": skill["inputs"], "outputs": skill["outputs"],
                       "permissions": skill["adapters"], "modes": skill["modes"], "limits": skill["limits"]})
    result.append({"name": NAMES[-1], "id": "correlation", "skills": [],
                   "inputs": ["assets", "evidence", "relationships"], "outputs": ["attack_surface_graph"],
                   "permissions": ["graph_write"], "modes": ["PASSIVE", "ACTIVE", "AUTHENTICATED"],
                   "limits": {"max_relationships": 1000}})
    return result
