# GitHub AI Red Teaming Tool Catalogue

This package contains a curated catalogue of 30 repositories and machine-readable agent skill manifests.

## Files
- `GitHub_AI_Red_Teaming_Tool_Catalogue_and_Agent_Skills.docx` — formatted training document.
- `GitHub_Tool_Catalogue_and_Agent_Skill_Integration.md` — linked Markdown catalogue.
- `github_tool_skill_registry.json` — structured skill registry for agent ingestion.
- `reference_standards.json` — standards and protocol references.

## Suggested use
Use the DOCX/Markdown to train operators and retrieve repository documentation. Use the JSON registry to configure agent skills and adapters. Before enabling a tool, pin a release/commit and verify its license, interface, security posture and supported inputs/outputs.

## Important
The JSON entries are integration metadata and suggested worker mappings, not executable tool schemas. Build and validate a dedicated adapter for each tool.
