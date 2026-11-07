# AI Red Teaming Comprehensive Agent Training Pack

Contents:
- `AI_Red_Teaming_Comprehensive_Skills_and_Agent_Training.docx` — human-readable curriculum.
- `comprehensive_skills_curriculum.md` — Markdown knowledge source.
- `skills_cards.jsonl` — 12 skill-domain records for RAG.
- `skills_curriculum.json` — structured skill and model candidate metadata.
- `agent_system_prompt.md` — proposed agent system instructions.
- `evaluation_questions.jsonl` — starter evaluation set.

Recommended ingestion:
1. Keep original OffSec course documents, existing 81 technique cards, and this 12-domain curriculum as distinct source collections.
2. Ingest each JSONL record as a separate retrieval document.
3. Preserve skill_id, source and provenance metadata.
4. Do not mix source-derived course claims with expanded technical synthesis.
5. Use a deterministic tool broker for every live action.
6. Evaluate candidate models on the supplied scorecard before deployment.

Model recommendation:
- GPT-6 Astra: primary candidate for complex reasoning, coding and multi-step agent work.
- GPT-6-Cyber: specialist candidate if approved access is available.
- Claude Opus 5.5 / Fable 5.1: independent reviewer candidates.
- Qwen / Llama: local/private candidates after exact model, license and provenance review.

No model is trusted by default. Capability does not replace application-level authorization, sandboxing, monitoring or human approval.
