import hashlib
import json
from collections import Counter

from ..database.store import Store
from ..evidence.integrity import validate
from ..schemas.models import IntelligencePayload

SECTIONS = {
    "External attack surface": {"domain", "ip"},
    "Network inventory": {"ip"},
    "Service inventory": {"service"},
    "Web/API inventory": {"application", "api"},
    "AI application inventory": {"application", "model_server"},
    "LLM and model inventory": {"model", "model_server"},
    "RAG inventory": {"rag"},
    "Embedding and vector inventory": {"embedding", "vector_database"},
    "Agent inventory": {"agent", "tool"},
    "MCP inventory": {"mcp_server"},
    "A2A inventory": {"a2a_service"},
    "Supply-chain inventory": {"repository", "dependency", "architecture_document"},
    "Cloud and container inventory": {"cloud_resource", "container"},
    "Identity and authentication inventory": {"identity"},
    "Defensive controls and telemetry": {"security_control", "telemetry"},
    "Trust boundaries": {"trust_boundary"},
}


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def port_lines(store: Store, identifier: str):
    offset = 0
    while records := store.ports(identifier, offset, 1000):
        for record in records:
            yield canonical(record) + b"\n"
        offset += len(records)


def inventory_descriptor(store: Store, identifier: str, known_evidence: set[str]) -> dict:
    digest = hashlib.sha256()
    for line in port_lines(store, identifier):
        record = json.loads(line)
        if not set(record["evidence_refs"]) <= known_evidence or (
            record["assessment_status"] == "completed" and not record["evidence_refs"]
        ):
            raise ValueError("Port inventory references missing evidence")
        digest.update(line)
    return {"format": "jsonl", "count": store.coverage(identifier)["total_ports"],
            "sha256": digest.hexdigest(), "url": f"/api/v1/recon/assessments/{identifier}/ports/export"}


def payload(store: Store, identifier: str) -> IntelligencePayload:
    assessment = store.assessment(identifier)
    if assessment["status"] in {"queued", "running"}:
        raise ValueError("Intelligence publication requires a terminal assessment")
    assets = store.assets(identifier)
    evidence = store.evidence(identifier)
    known = validate(evidence)
    graph = store.graph(identifier)
    for item in assets + graph["observed_edges"] + graph["inferred_edges"]:
        if not item["evidence_refs"] or not set(item["evidence_refs"]) <= known:
            raise ValueError("Intelligence references missing evidence")

    def select(kinds):
        return [item for item in assets if item["kind"] in kinds]

    return IntelligencePayload(
        assessment_id=identifier, created_at=assessment["created_at"],
        scope=assessment["spec"]["targets"] or [item["name"] for item in assessment["spec"]["inventory"]],
        mode=assessment["spec"]["mode"], execution_status=assessment["status"],
        assets=assets, services=select({"service"}), applications=select({"application", "api"}),
        ai_components=select({"model_server", "embedding", "vector_database", "tool"}),
        models=select({"model"}), rag_components=select({"rag"}), agents=select({"agent"}),
        mcp_servers=select({"mcp_server"}), a2a_services=select({"a2a_service"}),
        cloud_resources=select({"cloud_resource", "container"}), identities=select({"identity"}),
        trust_boundaries=select({"trust_boundary"}), ports=inventory_descriptor(store, identifier, known),
        graph=graph,
        evidence_references=[{key: item[key] for key in ("id", "source", "mode", "sha256")}
                             for item in evidence],
        coverage=store.coverage(identifier), limitations=assessment["limitations"],
    )


def markdown(store: Store, identifier: str) -> str:
    assessment = store.assessment(identifier)
    assets = store.assets(identifier)
    coverage = store.coverage(identifier)
    output = [
        "# Cyrblu Independent Reconnaissance Report", "",
        f"Assessment: {identifier}", f"Title: {assessment['spec']['title']}",
        f"Mode: {assessment['spec']['mode']}", f"Execution: {assessment['status']}",
        f"Authorization reference: {assessment['spec']['authorization_reference']}", "",
        "A completed workflow is not a security pass. Supplied assertions and inferred assets are not live verification.",
        "", "## Complete port inventory", "",
        f"Planned records: {coverage['total_ports']}; completed: {coverage['completed_ports']}; incomplete: {coverage['uncompleted_ports']}.",
        f"States: {json.dumps(coverage['states'], sort_keys=True)}",
        f"Full machine-readable inventory: /api/v1/recon/assessments/{identifier}/ports/export",
    ]
    for title, kinds in SECTIONS.items():
        selected = [item for item in assets if item["kind"] in kinds]
        output.extend(["", f"## {title}", ""])
        if not selected:
            output.append("Not observed or not assessed; absence is not established.")
        for item in selected:
            output.append(f"- {item['name']} [{item['kind']}], confidence {item['confidence']}, "
                          f"{'inferred/supplied' if item['inferred'] else 'observed'}; evidence {', '.join(item['evidence_refs'])}")
    graph = store.graph(identifier)
    output.extend(["", "## AI architecture graph", "",
                   f"Nodes: {len(graph['nodes'])}; observed relationships: {len(graph['observed_edges'])}; inferred relationships: {len(graph['inferred_edges'])}.",
                   f"Export: /api/v1/recon/assessments/{identifier}/graph", "", "## Unknown assets and confidence", "",
                   f"Inventory kinds: {dict(Counter(item['kind'] for item in assets))}.",
                   "Unknown service records remain in the complete port inventory. Exact model weights/versions are unverified.",
                   "", "## Incomplete discovery and limitations", ""])
    output.extend(f"- {item}" for item in assessment["limitations"])
    for item in store.evidence(identifier):
        observation = item["observation"]
        if observation.get("outcome") == "unverified":
            output.append(f"- {observation['target']}:{observation['port']}{observation['path']}: "
                          f"{observation['error_type']}; endpoint unverified ({item['id']}).")
    output.extend(["", "## Recommended next steps", "",
                   "Review authorization scope, validate supplied assertions, resolve incomplete ports and unsupported protocols, "
                   "supply architecture/identity/telemetry exports, and use the signed package to plan a separately authorized assessment.",
                   "", "## Evidence", ""])
    output.extend(f"- {item['id']}: {item['source']} ({item['mode']})" for item in store.evidence(identifier))
    return "\n".join(output) + "\n"
