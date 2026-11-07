import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..reporting.report import canonical
from ..schemas.models import IntelligencePackage, IntelligencePayload, Signature


def publish(payload: IntelligencePayload, private_path: Path) -> IntelligencePackage:
    if private_path.stat().st_mode & 0o077:
        raise ValueError("Signing key permissions must be 0600")
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Only Ed25519 signing keys are supported")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return IntelligencePackage(payload=payload, signature=Signature(
        key_id=hashlib.sha256(public).hexdigest(),
        value=base64.b64encode(key.sign(canonical(payload.model_dump()))).decode(),
    ))


def verify(document: dict, trusted_public_path: Path) -> IntelligencePackage:
    package = IntelligencePackage.model_validate(document)
    key = serialization.load_pem_public_key(trusted_public_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Only Ed25519 public keys are supported")
    public = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if package.signature.key_id != hashlib.sha256(public).hexdigest():
        raise ValueError("Package does not match pinned trusted signing key")
    key.verify(base64.b64decode(package.signature.value, validate=True), canonical(package.payload.model_dump()))
    return package
