from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

Mode = Literal["PASSIVE", "ACTIVE", "AUTHENTICATED"]
Kind = Literal[
    "domain", "ip", "port", "service", "application", "api", "model", "model_server", "rag",
    "embedding", "vector_database", "agent", "mcp_server", "a2a_service", "tool",
    "identity", "cloud_resource", "container", "dependency", "trust_boundary",
    "telemetry", "security_control", "repository", "architecture_document",
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InventoryItem(Contract):
    name: str = Field(min_length=1, max_length=300)
    kind: Kind
    source_reference: str = Field(min_length=1, max_length=500)
    attributes: dict[str, str] = Field(default_factory=dict, max_length=20)


class Relationship(Contract):
    source: str = Field(min_length=1, max_length=300)
    target: str = Field(min_length=1, max_length=300)
    relation: Literal["exposes", "resolves_to", "uses", "depends_on", "delegates_to", "data_flow", "crosses_boundary"]
    inferred: StrictBool = True
    confidence: float = Field(ge=0, le=1, default=0.5)
    source_reference: str = Field(min_length=1, max_length=500)


class Assessment(Contract):
    title: str = Field(min_length=1, max_length=120)
    mode: Mode = "PASSIVE"
    targets: list[str] = Field(default_factory=list, max_length=32)
    authorization_reference: str = Field(min_length=1, max_length=500)
    approved: StrictBool
    udp: StrictBool = False
    fingerprint_services: StrictBool = False
    inventory: list[InventoryItem] = Field(default_factory=list, max_length=1000)
    relationships: list[Relationship] = Field(default_factory=list, max_length=1000)


class IntelligencePayload(Contract):
    schema_version: Literal["1.0"] = "1.0"
    assessment_id: str
    created_at: str
    scope: list[str]
    mode: Mode
    execution_status: str
    assets: list[dict]
    services: list[dict]
    applications: list[dict]
    ai_components: list[dict]
    models: list[dict]
    rag_components: list[dict]
    agents: list[dict]
    mcp_servers: list[dict]
    a2a_services: list[dict]
    cloud_resources: list[dict]
    identities: list[dict]
    trust_boundaries: list[dict]
    ports: dict
    graph: dict
    evidence_references: list[dict]
    coverage: dict
    limitations: list[str]


class Signature(Contract):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str
    value: str


class IntelligencePackage(Contract):
    payload: IntelligencePayload
    signature: Signature
