import hashlib
import json
import html
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
    if sum(store.record_counts(identifier, "api_operation").values()) > 10000:
        raise ValueError("Complete API intelligence exceeds the 10,000-operation publication limit; use paginated intelligence records")
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
        scope=list(dict.fromkeys(assessment["spec"]["targets"] + assessment["spec"].get("urls", []) +
                                 [item["name"] for item in assessment["spec"]["inventory"]])),
        mode=assessment["spec"]["mode"], execution_status=assessment["status"],
        assets=assets, services=select({"service"}), applications=select({"application", "api"}) +
            [{**item, "kind": "api_operation"} for item in store.records(identifier, "api_operation", limit=10000)],
        ai_components=select({"model_server", "embedding", "vector_database", "tool"}),
        models=select({"model"}), rag_components=select({"rag"}), agents=select({"agent"}),
        mcp_servers=select({"mcp_server"}), a2a_services=select({"a2a_service"}),
        cloud_resources=select({"cloud_resource", "container"}), identities=select({"identity"}),
        trust_boundaries=select({"trust_boundary"}), ports=inventory_descriptor(store, identifier, known),
        graph=graph,
        evidence_references=[{key: item[key] for key in ("id", "source", "mode", "sha256")}
                             for item in evidence],
        coverage={**store.coverage(identifier), "api": assessment.get("api_coverage", {}),
                  "domains": assessment.get("domain_states", {}),
                  "recommended_next_actions": assessment.get("recommended_next_actions", [])}, limitations=assessment["limitations"],
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
    output.extend(["", "## API completeness", "", json.dumps(assessment.get("api_coverage", {}), sort_keys=True),
                   "", "## API endpoint-by-endpoint inventory", ""])
    for operation in store.records(identifier, "api_operation", limit=10000):
        output.append(f"- {operation['method']} {operation['path']}: analysis {operation['status']}; "
                      f"validation {operation.get('validation_status', 'unverified')}; "
                      f"authentication {operation.get('authentication', 'unknown')}; evidence {', '.join(operation['evidence_refs'])}.")
    for issue in store.records(identifier, "api_issue", limit=1000):
        output.append(f"- API discovery incomplete: {issue['source']}: {issue['reason']}.")
    for item in store.evidence(identifier):
        observation = item["observation"]
        if observation.get("outcome") == "unverified":
            output.append(f"- {observation['target']}:{observation['port']}{observation['path']}: "
                          f"{observation['error_type']}; endpoint unverified ({item['id']}).")
    output.extend(["", "## Recommended next steps", "",
                   "Review authorization scope, validate supplied assertions, resolve incomplete ports and unsupported protocols, "
                   "supply architecture/identity/telemetry exports, and use the signed package to plan a separately authorized assessment.",
                   ""])
    for action in assessment.get("recommended_next_actions", []):
        output.append(f"- Priority {action['priority']}: {action['asset']}: {action['intent']} "
                      f"Authorization: {action['required_authorization']}; confidence {action['confidence']}.")
    output.extend(["", "## Evidence", ""])
    output.extend(f"- {item['id']}: {item['source']} ({item['mode']})" for item in store.evidence(identifier))
    return "\n".join(output) + "\n"


def structured(store: Store, identifier: str) -> dict:
    assessment = store.assessment(identifier)
    return {"schema_version": "1.0", "assessment": assessment,
            "methodology": "Authorized bounded discovery and source-asserted document analysis; no exploitation.",
            "record_limits": {"api_operations": 10000, "api_specifications": 1000, "identity_inventory": 10000,
                              "supply_chain_inventory": 10000, "execution_history": 10000,
                              "remaining_records": "Use paginated intelligence/execution endpoints"},
            "tools": sorted({item["tool"] for item in store.executions(identifier, limit=10000)}),
            "coverage": {**store.coverage(identifier), "api": assessment.get("api_coverage", {})},
            "assets": store.assets(identifier), "graph": store.graph(identifier),
            "api_operations": store.records(identifier, "api_operation", limit=10000),
            "api_specifications": store.records(identifier, "api_specification", limit=1000),
            "identity_inventory": store.records(identifier, "ad_object", limit=10000),
            "supply_chain_inventory": store.records(identifier, "supply_chain_component", limit=10000),
            "execution_history": store.executions(identifier, limit=10000),
            "evidence": store.evidence(identifier), "limitations": assessment["limitations"]}


def html_report(store: Store, identifier: str) -> str:
    assessment = store.assessment(identifier)
    title = html.escape(assessment["spec"]["title"])
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<title>{title} - Reconnaissance</title></head><body><main>'
            f'<h1>{title}</h1><p>Independent reconnaissance report. Workflow completion is not security assurance.</p>'
            f'<pre>{html.escape(markdown(store, identifier))}</pre></main></body></html>')
