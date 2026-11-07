import json
import sys
from dataclasses import dataclass
from pathlib import Path

from ..database.store import Store
from ..schemas.models import InventoryItem


@dataclass(frozen=True)
class Skill:
    id: str
    agent: str
    kinds: tuple[str, ...]
    adapters: tuple[str, ...]
    modes: tuple[str, ...]
    max_items: int
    source: str


class Registry:
    def __init__(self):
        self.skills: dict[str, Skill] = {}
        roots = [Path(__file__).parent, Path(sys.prefix) / "share/cyrblu/recon/skills"]
        for root in roots:
            for path in sorted(root.glob("*/skill.json")):
                document = json.loads(path.read_text())
                if set(document) != {"id", "agent", "kinds", "adapters", "modes", "max_items"}:
                    raise ValueError(f"Invalid skill manifest: {path}")
                if not set(document["adapters"]) <= {"inventory", "nmap", "dns", "http"}:
                    raise ValueError("Skill cannot grant arbitrary tool execution")
                if not set(document["modes"]) <= {"PASSIVE", "ACTIVE", "AUTHENTICATED"}:
                    raise ValueError("Invalid skill modes")
                if not 1 <= document["max_items"] <= 1000:
                    raise ValueError("Invalid skill item limit")
                skill = Skill(document["id"], document["agent"], tuple(document["kinds"]),
                              tuple(document["adapters"]), tuple(document["modes"]), document["max_items"], str(path))
                if skill.id in self.skills:
                    prior = self.skills[skill.id]
                    if (skill.agent, skill.kinds, skill.adapters, skill.modes, skill.max_items) != (
                        prior.agent, prior.kinds, prior.adapters, prior.modes, prior.max_items
                    ):
                        raise ValueError("Installed skill conflicts with built-in approved permissions")
                self.skills[skill.id] = skill

    def authorize(self, skill_id: str, agent: str, adapter: str, mode: str) -> Skill:
        skill = self.skills[skill_id]
        if skill.agent != agent or adapter not in skill.adapters or mode not in skill.modes:
            raise ValueError("Agent/skill/adapter/mode permission denied")
        if mode != "ACTIVE" and adapter != "inventory":
            raise ValueError("PASSIVE/AUTHENTICATED export modes cannot invoke network adapters")
        return skill

    def ingest(self, skill_id: str, identifier: str, mode: str, items: list[InventoryItem], store: Store) -> int:
        skill = self.skills[skill_id]
        self.authorize(skill_id, skill.agent, "inventory", mode)
        selected = [item for item in items if item.kind in skill.kinds]
        if len(selected) > skill.max_items:
            raise ValueError("Agent input limit exceeded")
        for item in selected:
            ref = store.capture(identifier, item.source_reference, mode, {
                "agent": skill.agent, "skill": skill.id, "item": item.model_dump(),
                "basis": "customer_supplied_assertion_not_live_validation",
            })
            store.asset(identifier, item.kind, item.name, ref, item.attributes, inferred=True, confidence=0.7)
        store.event(identifier, skill.agent, "Inventory skill completed", {"skill": skill.id, "items": len(selected)})
        return len(selected)

    def describe(self) -> list[dict]:
        return [{
            "id": skill.id, "agent": skill.agent, "inputs": list(skill.kinds),
            "outputs": ["source-bound assets", "evidence references", "confidence"],
            "adapters": list(skill.adapters), "modes": list(skill.modes),
            "limits": {"max_items": skill.max_items},
            "inventory_capability": "customer_inventory_only",
            "live_connector": "registered_not_certified" if set(skill.adapters) - {"inventory"} else "not_implemented",
        } for skill in self.skills.values()]
