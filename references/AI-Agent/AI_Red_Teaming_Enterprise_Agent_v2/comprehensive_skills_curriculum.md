# AI Red Teaming Agent — Comprehensive Skills & Training Curriculum
**Version 1.0 | 7 November 2026 | Companion to the 11-module OSAI+/AI-300 course and 81-technique guide**

## Executive summary
This document extends the uploaded OSAI+/AI-300 course with the engineering, application-security, infrastructure, identity, research and reporting skills needed to assess complete AI-enabled systems. It is structured for RAG ingestion and agent evaluation.

## How to use this curriculum
- Keep the original 11 course modules as a separate source collection.
- Keep the existing 81 technique cards in a separate technique collection.
- Use each skill domain below as an additional knowledge collection.
- Keep course-derived facts separate from expanded technical guidance.
- Do not fine-tune model weights merely by uploading this document. Start with RAG, system instructions and evaluation.

## 12 skill domains
### S01 — Web application and API security
**Coverage:** Web application and API security
**Purpose:** Understand and assess the web/API layer that exposes AI functionality; identify whether security failures are in the model, application, identity layer or backend.
**Safe labs:**
- Build a local FastAPI service with login, a read-only search endpoint and a mock write endpoint. Test authentication and object-level authorization using two synthetic users.
- Use Burp Suite or OWASP ZAP against the local app to inspect requests, sessions, headers, API schemas and error handling.
- Create a safe SSRF design review using a mock URL-fetcher and allowlist test cases; do not target real internal services.
**Evidence and outputs:** HTTP request/response captures with secrets redacted; endpoint inventory; auth matrix; reproducible test cases; remediation notes.
**Mastery checks:**
- Explain IDOR/BOLA vs authentication failure.
- Show why an API gateway does not replace object-level authorization.
- Identify safe validation for SSRF, injection and path traversal.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S02 — Python and security automation
**Coverage:** Python and security automation
**Purpose:** Build repeatable, auditable test harnesses for AI endpoints and security workflows.
**Safe labs:**
- Write an async client that submits a fixed benign prompt suite to a local LLM endpoint and stores model/version, response, latency and test ID.
- Build a JSONL parser that validates technique-card schema and flags missing provenance fields.
- Create unit tests for URL allowlists, path canonicalization and structured tool arguments.
**Evidence and outputs:** Version-controlled scripts; dependency lockfile; unit-test results; JSONL outputs; reproducibility notes.
**Mastery checks:**
- Explain async vs sync I/O.
- Build a safe API test harness with timeouts and rate limits.
- Avoid shell interpolation and unsafe deserialization.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S03 — Linux, networking and operating systems
**Coverage:** Linux, networking and operating systems
**Purpose:** Understand the runtime and network context of AI services.
**Safe labs:**
- Deploy a local API and vector database in separate containers; inspect ports, DNS, routes and logs.
- Compare file permissions and process identities for an app and sidecar in a disposable VM.
- Trace a request through reverse proxy → app → model endpoint using local logs and packet metadata.
**Evidence and outputs:** Architecture diagram; service inventory; process/identity table; firewall and network-policy observations.
**Mastery checks:**
- Explain TCP handshake, DNS resolution and TLS verification.
- Explain Linux process identity and filesystem permissions.
- Identify why network reachability is not equivalent to application authorization.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S04 — Machine learning and deep learning
**Coverage:** Machine learning and deep learning
**Purpose:** Understand the model lifecycle and technical causes of AI-specific security behavior.
**Safe labs:**
- Train a small classifier on synthetic data and measure how label noise changes results.
- Inspect tokenization and embedding dimensions for synthetic sentences.
- Compare base model, instruction-tuned model and quantized inference behavior using a fixed evaluation set.
**Evidence and outputs:** Notebook, dataset provenance, model card, evaluation metrics and repeatable experiment.
**Mastery checks:**
- Explain attention and tokenization at a conceptual level.
- Distinguish training, fine-tuning and inference.
- Explain why embedding similarity is not text identity.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S05 — LLM application engineering
**Coverage:** LLM application engineering
**Purpose:** Understand how prompts, API calls, tools, context, state and guardrails are assembled into an application.
**Safe labs:**
- Build a toy assistant with separate system/user messages and structured JSON output.
- Add a mock tool with read-only and simulated write actions; require explicit approval for the latter.
- Test prompt injection with harmless canary strings and measure policy adherence across repeated runs.
**Evidence and outputs:** Prompt/version registry; tool-call logs; policy decision logs; regression test suite.
**Mastery checks:**
- Explain roles and context windows.
- Explain why system prompts are not secrets or authorization boundaries.
- Validate tool arguments outside the model.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S06 — RAG engineering and vector databases
**Coverage:** RAG engineering and vector databases
**Purpose:** Build and test a complete retrieval pipeline, including access controls and provenance.
**Safe labs:**
- Create a local ChromaDB corpus with public and restricted synthetic documents; test ACL filtering using two users.
- Compare fixed chunk sizes, overlap, BM25, dense and hybrid retrieval on a small labelled corpus.
- Introduce one benign poisoned document in a separate test index and measure ranking and citation changes.
**Evidence and outputs:** Ingestion manifest; chunk IDs; retrieval traces; ranking metrics; ACL test results; source citations.
**Mastery checks:**
- Explain chunking and Top-K.
- Explain BM25 vs dense retrieval.
- Explain why ACLs must be enforced before retrieved text enters model context.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S07 — Agent engineering and orchestration
**Coverage:** Agent engineering and orchestration
**Purpose:** Understand stateful agents, graph execution, tool delegation and multi-agent trust.
**Safe labs:**
- Build a LangGraph workflow with researcher, analyst and reviewer nodes; log every state transition.
- Add checkpointing and test whether a synthetic untrusted note can alter a later session.
- Use a mock executor and verify the graph cannot skip a required approval node.
**Evidence and outputs:** Graph definition; state schema; checkpoint policy; node-level logs; transition test results.
**Mastery checks:**
- Explain graph state and conditional edges.
- Explain confused-deputy risk.
- Explain why each tool action requires independent authorization.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S08 — MCP, A2A and protocol security
**Coverage:** MCP, A2A and protocol security
**Purpose:** Assess protocol-level discovery, identity, metadata, tools, resources and inter-agent trust.
**Safe labs:**
- Create a local MCP server with a read-only search tool and mock note-creation tool; inspect schemas before invocation.
- Create a local Agent Card and verify endpoint identity and authentication in a mock registry.
- Test a benign malformed tool argument and confirm strict schema validation rejects it.
**Evidence and outputs:** Tool/resource inventory; protocol traces; Agent Card snapshot; identity and permission matrix.
**Mastery checks:**
- Explain MCP roles and transports.
- Explain Agent Card as metadata rather than authorization.
- Explain provenance and authentication for agent-to-agent messages.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S09 — Cloud, containers and Kubernetes security
**Coverage:** Cloud, containers and Kubernetes security
**Purpose:** Understand how model endpoints, vector stores, storage, workload identities and Kubernetes workloads are secured.
**Safe labs:**
- Deploy a demo model API to a local Kubernetes cluster; inspect service accounts, RBAC and network policies.
- Use cloud policy simulation or read-only audit to compare required and effective permissions.
- Scan a demo image and generate an SBOM; review non-root execution, capabilities and mounts.
**Evidence and outputs:** Kubernetes manifests; RBAC review; image digest/SBOM; policy simulation; network diagram.
**Mastery checks:**
- Explain workload identity and role assumption.
- Explain Kubernetes service account and RBAC relationships.
- Identify an overprivileged pod without exercising its privileges.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S10 — AI/ML supply-chain security
**Coverage:** AI/ML supply-chain security
**Purpose:** Protect the code, dependencies, datasets, model weights, adapters, tokenizers and build pipeline.
**Safe labs:**
- Generate an SBOM for a demo Python AI app and compare pinned vs unpinned dependencies.
- Review a model-loading path for unsafe pickle use; validate statically or with harmless fixtures only.
- Compare signed and unsigned synthetic model artifacts and run a fixed behavior regression suite.
**Evidence and outputs:** SBOM; lockfiles; artifact hashes; signature validation; dataset lineage; evaluation deltas.
**Mastery checks:**
- Explain model provenance and artifact integrity.
- Explain unsafe deserialization risk.
- Explain why a model registry is a trust boundary.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S11 — Enterprise identity and Windows/AD security
**Coverage:** Enterprise identity and Windows/AD security
**Purpose:** Understand enterprise identity paths that may surround an AI deployment or appear in an integrated capstone.
**Safe labs:**
- Build a disposable Windows/AD lab and map users, groups, service accounts, shares and trust relationships.
- Use read-only directory queries to document permissions and service-account scope.
- Review a mock service configuration for excessive rights without attempting domain escalation.
**Evidence and outputs:** AD object map; identity matrix; share ACL report; evidence references; remediation plan.
**Mastery checks:**
- Explain Kerberos vs NTLM at a high level.
- Explain service-account risk and delegation.
- Separate proven access from assumed privilege escalation.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

### S12 — AI security research, detection and reporting
**Coverage:** AI security research, detection and reporting
**Purpose:** Turn observations into reproducible findings, defensible risk ratings, detections and remediation guidance.
**Safe labs:**
- Create a detection matrix for prompt injection, suspicious retrieval, tool invocation and cross-session memory access using synthetic events.
- Map selected scenarios to MITRE ATLAS and OWASP LLM guidance with rationale.
- Write a report containing evidence, scope, impact, confidence, limitations, remediation and retest criteria.
**Evidence and outputs:** Detection rules; event schema; technique mapping; final report; retest checklist.
**Mastery checks:**
- Distinguish observed evidence from inference.
- Write a finding with root cause and business impact.
- Propose a measurable retest.
**Safety:** Use only explicitly authorised systems. Prefer local disposable labs, synthetic data, read-only validation and dry-run sinks. Do not reuse course credentials, secrets, target addresses or lab access details.

## Recommended model candidates (official provider documentation checked 7 November 2026)

### Important principle: no model is trusted by default
A model can be capable without being secure for your workload. Evaluate each candidate on your own threat model, source grounding, tool-call correctness, prompt-injection robustness, refusal consistency, data handling, licensing, availability and cost. Use least privilege and deterministic policy enforcement regardless of model choice.

### GPT-6 Astra — OpenAI
**Role:** Primary reasoning and orchestration model
**Why it is a candidate:** Official model documentation positions it for demanding reasoning, coding, computer use, research and multi-step professional workflows. The model page lists function calling, structured outputs, code interpreter, hosted shell, Skills, MCP and computer-use capabilities.
**Recommendation:** Best first candidate for the main AI Red Teaming Agent, provided the account/API access, data handling and policy fit your engagement requirements. Use high reasoning for architecture analysis, attack-chain reasoning, code review and report synthesis.
**Caveat:** Do not infer authorization to conduct live cyber operations from model capability. Verify current API availability, pricing, retention, data residency and safety conditions.

### GPT-6-Cyber — OpenAI
**Role:** Specialized cybersecurity assistant/model option
**Why it is a candidate:** The current OpenAI model catalog lists GPT-6-Cyber as a specialized cyber model for investigating vulnerabilities, reproducing them in authorized test environments and verifying fixes.
**Recommendation:** Evaluate it as a specialist for authorized vulnerability research and validation if access is available to your account or organization.
**Caveat:** Availability and eligibility may be restricted. Confirm access through official OpenAI channels; do not build the architecture assuming it is universally available.

### Claude Opus 5.5 / Claude Fable 5.1 — Anthropic
**Role:** Independent second-opinion model
**Why it is a candidate:** Anthropic's current model documentation describes Opus for long-running agentic coding and knowledge work and Fable for demanding reasoning and long-horizon agentic work.
**Recommendation:** Use as an independent reviewer for code analysis, threat-model critique, test-plan review and cross-checking findings. Compare on your own benchmark before selecting.
**Caveat:** Treat as a second opinion, not a source of truth. Validate tool permissions, data handling and model-specific safeguards.

### Qwen family (select an appropriate current instruction/coding model) — Qwen / Alibaba
**Role:** Self-hosted or private-environment candidate
**Why it is a candidate:** The official Qwen model site describes a broad open foundation model family covering language, vision, code, math and reasoning, with multiple sizes and architectures.
**Recommendation:** Consider for local/private inference, offline lab experiments, custom evaluation and privacy-sensitive workflows where you control hosting. Select a specific checkpoint only after reviewing its exact license, model card, benchmark and hardware requirements.
**Caveat:** Open weights do not automatically mean secure, unbiased, safe, or suitable for commercial use. Verify license, provenance, vulnerabilities, quantization and tool-calling reliability.

### Meta Llama family — Meta
**Role:** Alternative self-hosted model family
**Why it is a candidate:** Meta provides official model, hosting, integration and protection resources, and publishes model-specific license and use policies.
**Recommendation:** Include a Llama checkpoint in the local-model bake-off if your hosting environment, license and application stack fit it.
**Caveat:** Review the exact model version's license and acceptable-use terms; evaluate security behavior and tool calling independently.

## Suggested model architecture
1. Primary orchestrator/reasoner: GPT-6 Astra for demanding analysis and multi-step workflows, subject to access, cost and data governance.
2. Cyber-specialist evaluation: GPT-6-Cyber if approved access is available; use it for authorized vulnerability research and fix verification.
3. Independent reviewer: Claude Opus 5.5 or Fable 5.1 to critique threat models, code analysis and findings.
4. Local/private candidate: a current Qwen or Llama checkpoint for local lab and privacy-controlled experiments after license and model-card review.
5. Deterministic tool broker: a separate policy service that checks scope, identity, schemas, allowlists, approvals, sandbox boundaries and audit logging. The LLM never directly grants itself permission.

## Model evaluation scorecard
| Dimension | Suggested test | Weight |
|---|---|---:|
| Reasoning quality | Multi-step architecture and attack-path scenario with evidence constraints | 20% |
| Coding | Build/fix a safe API test harness and unit tests | 15% |
| Source grounding | Questions answerable only from supplied course files; require citations | 15% |
| Tool correctness | Schema-valid calls and no unintended side effects | 15% |
| Authorization/safety | Reject out-of-scope tests and require approval for state changes | 15% |
| Prompt-injection robustness | Benign canaries in user, document and tool outputs | 10% |
| Privacy | Synthetic cross-tenant and memory-isolation tests | 5% |
| Reliability | Repeat fixed test suite and measure variance/regression | 5% |

These are proposed evaluation weights, not published benchmark results.

## 16-week learning sequence
| Phase | Weeks | Outcome |
|---|---:|---|
| Foundations | 1–2 | Web/API, Python, Linux and networking |
| AI foundations | 3–4 | ML, transformers, tokenization, embeddings and inference |
| LLM application | 5–6 | Model APIs, prompts, tools, RAG and vector stores |
| Agentic systems | 7–8 | LangGraph, memory, MCP, A2A and workflow controls |
| Offensive AI | 9–11 | Agent, RAG, embedding, protocol and supply-chain assessments |
| Infrastructure | 12–13 | Cloud IAM, Docker, Kubernetes and enterprise identity |
| Capstone | 14–15 | Integrated authorised assessment and reporting |
| Exam readiness | 16 | Scenario drills, source-grounded answers and revision |

## Recommended lab projects
1. Vulnerable-but-contained chatbot: prompt handling, authentication, mock backend and tool boundaries.
2. RAG lab: ChromaDB, BM25, synthetic restricted documents, retrieval ACLs and poisoning detection.
3. Multi-agent LangGraph lab: researcher, analyst and reviewer with explicit state and approval gates.
4. MCP/A2A lab: local server, read-only and mock write tools, Agent Card registry and message provenance.
5. Cloud-native AI lab: model API and vector store on Kubernetes with workload identity, RBAC and network policies.
6. Supply-chain lab: SBOM, signed artifacts, safe deserialization review and dataset lineage.
7. Enterprise capstone: public app, AI assistant, backend mock, gateway and isolated AD test environment.

## Agent operating requirements
Use `agent_system_prompt.md`. The agent must ask for scope when missing, label course-derived versus additional knowledge, use synthetic examples, collect evidence, distinguish demonstrated impact from inference and recommend retesting.

## Official model references
- OpenAI model catalog: https://developers.openai.com/api/docs/models
- OpenAI GPT-6 guide: https://developers.openai.com/api/docs/guides/latest-model
- OpenAI GPT-6 Astra model page: https://developers.openai.com/api/docs/models/gpt-6-astra
- Anthropic model overview: https://platform.claude.com/docs/en/models/overview
- Qwen official model family: https://qwen.moe/
- Meta Llama developer portal: https://dev.meta.ai/llama

Model capability descriptions were checked on 7 November 2026. Availability, names, pricing, licensing and access can change; verify before implementation.