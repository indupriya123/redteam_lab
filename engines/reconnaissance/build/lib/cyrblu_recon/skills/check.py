import argparse
import json
import tempfile
from pathlib import Path

from ..database.store import Store
from ..schemas.models import InventoryItem
from .registry import Registry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    document = json.loads(args.manifest.read_text())
    registry = Registry()
    skill = registry.skills[document["id"]]
    expected = {"id": skill.id, "agent": skill.agent, "kinds": list(skill.kinds),
                "adapters": list(skill.adapters), "modes": list(skill.modes), "max_items": skill.max_items}
    if document != expected:
        raise ValueError("Manifest differs from approved skill contract")
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "test.sqlite3")
        item = InventoryItem(kind=skill.kinds[0], name="synthetic-fixture", source_reference="golden-fixture")
        assert registry.ingest(skill.id, "fixture", "PASSIVE", [item], store) == 1
        assert store.assets("fixture")[0]["inferred"]
        try:
            registry.authorize(skill.id, "unauthorized-agent", "inventory", "PASSIVE")
        except ValueError:
            pass
        else:
            raise AssertionError("Agent permission check failed")
    print(f"{skill.id}: contract, synthetic ingestion, and agent isolation passed")


if __name__ == "__main__":
    main()
