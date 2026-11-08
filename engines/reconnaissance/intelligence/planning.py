import hashlib
import json
from pathlib import Path


def build_plan(identifier, store, registry):
    rules = json.loads((Path(__file__).parents[1] / "config/discovery-rules.json").read_text())
    for rule in rules:
        if set(rule) != {"id", "kind", "skill", "priority", "intent"} or rule["skill"] not in registry.skills or not 0 <= rule["priority"] <= 1:
            raise ValueError("Invalid trusted discovery rule")
    actions = []
    for asset in store.assets(identifier):
        for rule in rules:
            if asset["kind"] != rule["kind"]:
                continue
            key = hashlib.sha256(f"{rule['id']}:{asset['id']}".encode()).hexdigest()
            confidence = asset["confidence"]
            action = {"rule": rule["id"], "asset_id": asset["id"], "asset": asset["name"],
                      "skill": rule["skill"], "priority": round(rule["priority"] * confidence, 3),
                      "intent": rule["intent"], "basis": "source_asserted_or_inferred" if asset["inferred"] else "observed",
                      "confidence": confidence, "required_authorization": "separate_scope_and_read_only_profile",
                      "automatic_execution": False, "classification": "assessment_opportunity_not_vulnerability"}
            source = asset.get("source", asset["evidence_refs"][0])
            store.record(identifier, "assessment_plan", key, action, source, asset["evidence_refs"], "approval_required")
            actions.append(action)
            if len(actions) == 500:
                store.event(identifier, "correlation", "Recommendation budget reached; remaining prioritization incomplete")
                return sorted(actions, key=lambda item: item["priority"], reverse=True)
    return sorted(actions, key=lambda item: item["priority"], reverse=True)
