import hashlib
import json


def validate(documents: list[dict]) -> set[str]:
    references = set()
    for document in documents:
        content = {key: document[key] for key in ("timestamp", "source", "mode", "observation")}
        digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
        if document["id"] != digest or document["sha256"] != digest:
            raise ValueError("Reconnaissance evidence integrity validation failed")
        references.add(digest)
    return references
