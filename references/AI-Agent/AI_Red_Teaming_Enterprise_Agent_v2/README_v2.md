# Enterprise AI Red Teaming Agent — v2

This package extends the existing 11-module course curriculum, 81 technique cards and 12 domain skill cards.

## New additions
- `enterprise_technique_extensions.jsonl` — additional technique records.
- `enterprise_agent_capabilities.json` — enterprise capability catalogue.
- `enterprise_agent_system_prompt_v2.md` — expanded agent instructions.
- `additional_capabilities_and_runbooks.md` — architecture, workflow, integrations, evaluation and operational playbooks.
- `enterprise_evaluation_cases.jsonl` — additional benchmark scenarios.
- `Enterprise_AI_Red_Teaming_Agent_Comprehensive_Training_v2.docx` — consolidated handbook.

## Suggested ingestion order
1. `comprehensive_skills_curriculum.md`
2. `technique_by_technique_guide.md`
3. `additional_capabilities_and_runbooks.md`
4. `enterprise_agent_system_prompt_v2.md`
5. Technique and skill JSONL files as structured retrieval records
6. Evaluation JSONL files as benchmark fixtures

Preserve source labels, version, module, domain and evidence metadata when chunking/indexing. Do not merge benchmark expected outcomes into the agent's runtime knowledge if doing so would leak answers during evaluation; keep evaluation fixtures in a separate test collection.
