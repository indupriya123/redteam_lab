# Repository assessment - November 8, 2026

## Existing architecture and reusable components

The workspace is not a Git repository. The source has two Python distributions:
`lab-redteam` and independently installable `cyrblu-reconnaissance`. There is no
existing LangGraph, PostgreSQL, Redis, ChromaDB, Neo4j, MinIO, or PDF integration.
Reference documents name those technologies; references are not implementations.

| Area inspected | Existing implementation | Reuse / gap |
|---|---|---|
| Packages and directory structure | Root `pyproject.toml`; independent engine `pyproject.toml`; 22 skill distributions | Preserve both distribution boundaries |
| Reconnaissance | `orchestrator/engine.py`, `tools/nmap.py`, `tools/dns.py`, `tools/http.py` | Reuse scoped batching, XML validation and bounded observations |
| Agents and workflows | 23 permissioned definitions; asyncio inventory/domain dispatch | No LangGraph workflow or autonomous LLM planning |
| API services | Two separate FastAPI applications | Extend reconnaissance endpoints without importing its execution code into red team |
| Database models | Separate SQLite assessment/evidence/asset/relationship/port/event storage | Add versioned, additive migrations and normalized API/execution records |
| PostgreSQL | None | A distributed production store remains future work |
| Redis | None; bounded in-process queue and process ownership lock | Preserve single-instance operation; not distributed queue readiness |
| ChromaDB | None | No semantic search or deployed vector intelligence service |
| Ollama | Root application's local advisory review | Execution remains deterministic; do not give advisory models scope authority |
| Frontends | Separate bundled HTML/CSS/JS dashboards | Extend current reconnaissance workspace; no new frontend stack |
| Logging/monitoring | Python logging; durable event cursor; SSE and browser polling | Add individual tool execution records and API completeness views |
| Reporting | Markdown, graph JSON, signed Ed25519 package; SHA256-bound JSONL port export | Add structured JSON/escaped HTML and endpoint reports; PDF not present |
| Tools | Recon Nmap/DNS/HTTP adapters; root curated Nuclei and bounded Nmap | Keep curated adapters; distinguish executable adapters from catalogue entries |
| Configuration/deployment | Python launchers, tokens, env configuration; isolated fixture Docker recipe | No deployed containers, Kubernetes cluster or managed services |
| Tests | 102 passing checks, two deliberately skipped native full-scan checks at previous handoff | Expand golden suite; do not convert skipped certification to success |

## Measured development-host availability

macOS development host, not Kali. Nmap, Masscan, RustScan, NetExec, Certipy,
Docker, TShark, Trivy, LangGraph, PostgreSQL/Redis/ChromaDB Python clients were
unavailable at assessment. `ldapsearch`, Git and Nuclei executables were found.
Existence alone does not validate a command adapter or authorized target access.
No customer LDAP/cloud/Kubernetes credentials or Windows lab were supplied.

## Technical debt and missing functionality

The original recon sequence is fixed and aborts on one scanner failure. HTTP
discovery reads selected metadata but does not retain/parse complete API
operations. Assets deduplicate but have limited lifecycle metadata. API
completeness, durable execution records, per-domain selection, document import,
recursive reference controls, denylists and explicit URL scope are missing.
The dashboard primarily renders JSON. Generated `build/` directories are
packaging artifacts, not alternate implementations.

Live AD/AD CS, authenticated cloud/Kubernetes, protocol-complete MCP, agent/RAG
internals, subdomain/CT vendors, broad tool adapters, distributed persistence,
LLM planning, production privilege separation and PDF export are not present.
No placeholder will be relabeled as a working integration.

## Architectural decision

Extend the current independently deployable engine and existing asyncio,
FastAPI, SQLite, HTTPX, evidence and signing mechanisms. SQLite is retained for
the current single-worker local service; introducing PostgreSQL/Redis/LangGraph
without an existing integration would duplicate working infrastructure rather
than reuse it. Distributed production operation remains explicitly unsupported.
Add domain components, not one giant reconnaissance agent.

API-only discovery must not require Nmap. Complete operation parsing must be
usable offline. URL origins must be explicitly approved and resolved addresses
rechecked/pinned before every connection. LLM interpretation is not needed to
enforce deterministic scope and read-only execution.

## Implementation sequence

1. Add additive database migrations, domain selection, URL/exclusion policy and
   durable execution/completeness records.
2. Implement complete OpenAPI/Swagger JSON/YAML operation parsing, scoped
   reference recursion, documented/discovered route comparison, and explicit
   non-destructive GET profiles.
3. Add independently usable customer-export intelligence for BloodHound and
   supply-chain/SBOM data, without credential collection or invented CVEs.
4. Integrate existing event streaming, API inventories, graphs, JSON/HTML/
   Markdown reports and signed downstream handoff.
5. Exercise real loopback API fixtures, malformed/circular references, refusal
   boundaries, cancellation, dependency failures, migrations and regressions.
6. Publish the actual completion matrix. Native Kali/Windows/cloud/container
   certification requires the unavailable tools and authorized lab integrations;
   these are external blockers, not implemented capabilities.
