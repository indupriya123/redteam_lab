import json
from pathlib import Path


def load_catalogue(root: Path) -> dict:
    pack = root / "AI_Red_Teaming_Comprehensive_Agent_Training_Pack"
    enterprise = root / "AI_Red_Teaming_Enterprise_Agent_v2"
    techniques = []
    for path, prefix in [
        (pack / "technique_cards.jsonl", None),
        (enterprise / "enterprise_technique_extensions.jsonl", "ENT"),
    ]:
        for index, line in enumerate(path.read_text().splitlines(), 1):
            record = json.loads(line)
            if prefix:
                record["source_id"] = record["id"]
                record["id"] = f"{prefix}-{index:03}"
            record["source_file"] = str(path.relative_to(root))
            record["source_line"] = index
            record["execution_status"] = "reference_only"
            techniques.append(record)
    skills = [
        json.loads(line)
        for line in (pack / "skills_cards.jsonl").read_text().splitlines()
    ]
    return {
        "techniques": techniques,
        "skills": skills,
        "capabilities": json.loads(
            (enterprise / "enterprise_agent_capabilities.json").read_text()
        ),
        "execution_note": (
            "111 reference records, with overlapping techniques; not 111 executable tests. "
            "Only the separate built-in adapters can execute."
        ),
    }
