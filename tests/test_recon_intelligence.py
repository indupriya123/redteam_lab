import asyncio
import base64
import copy
import hashlib
import json
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lab_redteam.recon_intelligence import ARRAY_FIELDS, fetch, verify


@pytest.fixture
def publication(tmp_path):
    key = Ed25519PrivateKey.generate()
    trusted_key = tmp_path / "trusted.pub"
    trusted_key.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    token = tmp_path / "viewer.token"
    token.write_text("synthetic-token-not-an-actual-credential")
    token.chmod(0o600)
    payload = {name: [] for name in ARRAY_FIELDS}
    payload.update(schema_version="1.0", assessment_id=str(uuid.uuid4()), created_at="2026-11-07T00:00:00Z",
                   scope=["127.0.0.1"], mode="ACTIVE", execution_status="completed",
                   ports={"count": 65535}, graph={}, coverage={"security_pass": False},
                   limitations=["Synthetic publication fixture"])
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    document = {"payload": payload, "signature": {"algorithm": "Ed25519", "key_id": hashlib.sha256(raw).hexdigest(),
                                                 "value": base64.b64encode(key.sign(canonical)).decode()}}
    return document, trusted_key, token


def test_consumes_only_versioned_verified_api_package(publication):
    document, key, token = publication

    def handler(request):
        assert request.headers["authorization"] == "Bearer " + token.read_text()
        assert request.url.path.endswith("/intelligence")
        return httpx.Response(200, json=document)

    result = asyncio.run(fetch(document["payload"]["assessment_id"], "http://127.0.0.1:8090", token, key,
                               transport=httpx.MockTransport(handler)))
    assert result == document


@pytest.mark.parametrize("change", ["tamper", "version", "algorithm", "security_pass", "extra"])
def test_rejects_tampered_or_invalid_package(publication, change):
    document, key, _ = publication
    changed = copy.deepcopy(document)
    if change == "tamper":
        changed["payload"]["limitations"].append("tampered")
    elif change == "version":
        changed["payload"]["schema_version"] = "2.0"
    elif change == "algorithm":
        changed["signature"]["algorithm"] = "none"
    elif change == "security_pass":
        changed["payload"]["coverage"]["security_pass"] = True
    else:
        changed["payload"]["unrecognized"] = "field"
    with pytest.raises(ValueError):
        verify(changed, key)


def test_rejects_remote_integration_and_redirect(publication):
    document, key, token = publication
    identifier = document["payload"]["assessment_id"]
    with pytest.raises(ValueError, match="loopback"):
        asyncio.run(fetch(identifier, "http://remote.invalid", token, key))
    with pytest.raises(ValueError, match="302"):
        asyncio.run(fetch(identifier, "http://127.0.0.1:8090", token, key,
                          transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": "http://remote.invalid"}))))
