import base64
import hashlib
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

ARRAY_FIELDS = (
    "assets", "services", "applications", "ai_components", "models", "rag_components",
    "agents", "mcp_servers", "a2a_services", "cloud_resources", "identities", "trust_boundaries",
    "evidence_references",
)
PAYLOAD_FIELDS = set(ARRAY_FIELDS) | {
    "schema_version", "assessment_id", "created_at", "scope", "mode", "execution_status",
    "ports", "graph", "coverage", "limitations",
}


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid")
    algorithm: Literal["Ed25519"]
    key_id: str
    value: str


class PublishedPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: dict = Field(max_length=len(PAYLOAD_FIELDS))
    signature: Signature


def verify(document: dict, trusted_key: Path) -> dict:
    package = PublishedPackage.model_validate(document)
    payload = package.payload
    if set(payload) != PAYLOAD_FIELDS or payload["schema_version"] != "1.0":
        raise ValueError("Unsupported reconnaissance intelligence contract")
    if payload["mode"] not in {"ACTIVE", "PASSIVE", "AUTHENTICATED"} or payload["execution_status"] not in {
        "completed", "cancelled", "interrupted", "failed",
    }:
        raise ValueError("Reconnaissance package is not a terminal, recognized assessment")
    uuid.UUID(payload["assessment_id"])
    if not isinstance(payload["created_at"], str):
        raise ValueError("Invalid reconnaissance publication timestamp")
    for name in ARRAY_FIELDS:
        if not isinstance(payload[name], list) or not all(isinstance(item, dict) for item in payload[name]):
            raise ValueError(f"Invalid reconnaissance {name} inventory")
    for name in ("scope", "limitations"):
        if not isinstance(payload[name], list) or not all(isinstance(item, str) for item in payload[name]):
            raise ValueError(f"Invalid reconnaissance {name}")
    for name in ("ports", "graph", "coverage"):
        if not isinstance(payload[name], dict):
            raise ValueError(f"Invalid reconnaissance {name}")
    key = serialization.load_pem_public_key(trusted_key.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Reconnaissance requires a pinned Ed25519 public key")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if hashlib.sha256(raw).hexdigest() != package.signature.key_id:
        raise ValueError("Reconnaissance signing key does not match pinned trust")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    try:
        key.verify(base64.b64decode(package.signature.value, validate=True), canonical)
    except InvalidSignature as exc:
        raise ValueError("Reconnaissance package signature is invalid") from exc
    if payload["coverage"].get("security_pass") is not False:
        raise ValueError("Reconnaissance cannot establish a security pass")
    return document


async def fetch(identifier: str, endpoint: str, token_path: Path, trusted_key: Path,
                transport: httpx.AsyncBaseTransport | None = None) -> dict:
    identifier = str(uuid.UUID(identifier))
    url = urlsplit(endpoint)
    if url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"} or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        raise ValueError("Reconnaissance integration must use an explicit loopback API endpoint")
    if token_path.stat().st_mode & 0o077:
        raise ValueError("Reconnaissance API token permissions must be 0600")
    token = token_path.read_text().strip()
    async with httpx.AsyncClient(timeout=30, trust_env=False, follow_redirects=False, transport=transport) as client:
        async with client.stream("GET", endpoint.rstrip("/") + f"/api/v1/recon/assessments/{identifier}/intelligence",
                                 headers={"Authorization": f"Bearer {token}"}) as response:
            if response.status_code != 200:
                raise ValueError(f"Reconnaissance API returned HTTP {response.status_code}")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > 8 * 1024 * 1024:
                    raise ValueError("Reconnaissance package exceeds 8 MiB")
    document = verify(json.loads(data), trusted_key)
    if document["payload"]["assessment_id"] != identifier:
        raise ValueError("Reconnaissance assessment does not match requested publication")
    return document
