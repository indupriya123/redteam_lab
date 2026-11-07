# Enterprise AI Red Team Agent — Additional Capabilities and Runbooks

## 1. Reference architecture
- **User / engagement console:** scope, authorization, objectives, test window, identities, approvals and reporting.
- **Orchestrator:** LangGraph-style state machine with explicit states, retries, checkpoints and human approval nodes.
- **Knowledge layer:** versioned course material, technique cards, enterprise standards, approved architecture docs and prior findings. Store source, version, date and access label with every chunk.
- **Policy broker:** deterministic enforcement for asset scope, identity, operation, argument schema, destination, rate, concurrency, risk tier and approval.
- **Execution workers:** isolated adapters for HTTP/API, browser, code analysis, cloud posture, Kubernetes, MCP/A2A protocol tests, RAG harnesses and observability.
- **Evidence store:** immutable run metadata, request/response references, hashes, redaction status and chain-of-custody.
- **Analysis and reporting:** finding correlation, attack-path graph, severity rationale, ticket creation and retest.
- **Human control plane:** approve high-impact tests, pause/stop, review findings and authorize retests.

## 2. Agent workflow state machine
1. `INTAKE` — validate scope and engagement configuration.
2. `ASSET_DISCOVERY` — passive inventory and fingerprinting.
3. `ARCHITECTURE_MODEL` — trust boundaries, data flows, identity and tool graph.
4. `TEST_PLANNING` — map techniques to assets and expected evidence.
5. `PASSIVE_VALIDATION` — configuration, code, schema and policy checks.
6. `ACTIVE_VALIDATION` — bounded approved test cases.
7. `CORRELATION` — correlate findings across layers.
8. `RISK_RANKING` — severity, confidence, business context.
9. `REPORTING` — executive and technical outputs.
10. `REMEDIATION_TRACKING` — owners, due dates and status.
11. `RETEST` — verify fixes and regression controls.
12. `CLOSED` — preserve evidence and lessons learned.

Every state transition should be auditable. Persist only necessary state; protect checkpoints against tampering and replay.

## 3. High-value additional capabilities
- **Enterprise attack-surface inventory:** Build a continuously refreshed inventory of applications, APIs, AI endpoints, agents, MCP servers, model endpoints, vector stores, cloud assets and identity boundaries. Output: Asset graph; owner; environment; exposure; evidence timestamp; confidence; source.
- **AI system fingerprinting:** Identify model families, serving layers, orchestration frameworks, retrieval components, tool interfaces, safety layers and observable version clues. Output: Fingerprint hypotheses with confidence and non-invasive evidence; never present inference as fact.
- **API contract and schema analysis:** Parse OpenAPI, GraphQL schemas, JSON schemas and observed request/response shapes to find auth gaps, overbroad operations, mass assignment and inconsistent validation. Output: Endpoint-to-role matrix; schema diff; authorization test cases; reproducible evidence.
- **Identity and authorization graph:** Model users, service accounts, roles, tokens, delegated identities, agent identities, resources and trust relationships as a graph. Output: Reachability paths; excessive privilege; confused-deputy candidates; owner and remediation.
- **Business-logic testing:** Derive workflows, state transitions, invariants, tenant boundaries, approval steps and abuse cases from application behavior. Output: Workflow model; invariant violations; test traces; business impact.
- **Tenant isolation validation:** Test cross-tenant object access, retrieval filtering, cache separation, memory separation and tool/data boundary enforcement. Output: Tenant matrix; negative tests; evidence of isolation or leakage.
- **Secrets exposure assessment:** Detect exposed credentials in repositories, logs, prompts, traces, configs, images and model artifacts; validate exposure without using secrets beyond approved proof. Output: Secret type, location, exposure window, affected identity, rotation recommendation.
- **Cloud control-plane assessment:** Assess IAM policies, workload identity, metadata access, storage exposure, network paths, serverless functions and managed AI services. Output: Policy findings; trust graph; cloud attack path; least-privilege fix.
- **Kubernetes and container assessment:** Review RBAC, service accounts, admission policies, secrets, network policies, pod security, image provenance and workload configuration. Output: Cluster posture; workload-to-permission map; safe proof; hardening diff.
- **CI/CD and software supply-chain assessment:** Review build permissions, workflow triggers, artifact provenance, dependency pinning, secret handling, model download paths and release approvals. Output: Pipeline trust map; provenance gaps; dependency and artifact findings.
- **RAG corpus governance:** Assess ingestion authorization, document provenance, chunk metadata, ACL propagation, deletion, freshness, source attribution and index lifecycle. Output: Corpus lineage; ACL test matrix; poisoning indicators; stale/deleted-content tests.
- **Vector database security:** Review network exposure, authentication, namespace/collection isolation, metadata filters, backups, encryption, index access and query logging. Output: Vector-store configuration findings; tenant-boundary tests; access evidence.
- **Agent memory and state security:** Assess short-term state, long-term memory, checkpoint stores, replay, cross-session boundaries, retention and data minimization. Output: State-flow diagram; session-isolation tests; retention findings.
- **Tool execution security:** Assess tool allowlists, argument validation, path constraints, network egress, process isolation, timeouts, output handling and approval gates. Output: Tool capability inventory; schema fuzz results; sandbox evidence; policy gaps.
- **MCP server assessment:** Assess server discovery, transport, authentication, tool/resource exposure, schema trust, permission scope, origin and server lifecycle. Output: MCP inventory; tool permission matrix; protocol traces; remediation.
- **A2A trust and delegation assessment:** Assess agent discovery, Agent Cards, identity proof, delegation chains, task authorization, message provenance, replay and trust policy. Output: Agent trust graph; delegation chain; spoofing/replay test results.
- **Model endpoint and inference security:** Assess authentication, rate limits, quotas, request size, context handling, streaming, error disclosure, model routing and tenant controls. Output: Endpoint controls matrix; abuse-resistance evidence; operational limits.
- **Observability and detection engineering:** Map test actions to logs, traces, alerts and incident workflows; identify blind spots and build detection logic. Output: Detection coverage matrix; sample events; Sigma-style logic where appropriate; runbook.
- **Exploitability and impact validation:** Use bounded proofs to establish reachability, confidentiality, integrity or availability impact without unnecessary data access or service disruption. Output: Minimal proof; impact chain; confidence; rollback/stop conditions.
- **Remediation verification and regression:** Convert findings into retests, unit/integration tests, policy-as-code checks and continuous controls. Output: Retest record; regression test; fixed/not-fixed/partially-fixed status.
- **Attack-path and risk prioritization:** Correlate exposure, exploit preconditions, identity reachability, data sensitivity, business criticality and control coverage. Output: Ranked paths; explainable score factors; uncertainty; owner.
- **Evidence and reporting automation:** Create reproducible evidence packages, timelines, executive summaries, technical findings and remediation tickets. Output: Evidence bundle; finding schema; report; ticket payload; audit trail.
- **Purple-team exercise orchestration:** Translate validated attack paths into detection exercises, coordinate defenders, replay safe test events and measure response. Output: Exercise plan; telemetry; detection and response metrics; lessons learned.
- **Continuous control validation:** Schedule scoped checks for drift in permissions, endpoints, model configurations, tool catalogs, RAG ACLs and supply-chain controls. Output: Baseline; drift event; owner; severity; trend.
- **AI red-team benchmark harness:** Run repeatable test suites against models, agents, RAG apps and tool chains using versioned prompts, fixtures, expected outcomes and scoring. Output: Benchmark report; reproducible run IDs; regression deltas; model/version comparisons.

## 4. Technique execution template
For every technique, the agent must record:
- Objective and security property being tested.
- Target asset and approved scope reference.
- Preconditions and test identity.
- Baseline behavior and expected secure behavior.
- Minimal validation method and stop condition.
- Actual result and raw evidence reference.
- Confidence and limitations.
- Business impact and correlated attack path.
- Remediation, compensating controls and retest steps.

## 5. Prioritization model
Use a transparent, explainable model rather than a single opaque LLM score. Evaluate:
- Internet or partner exposure.
- Exploit preconditions and required privileges.
- Identity reachability and privilege expansion.
- Sensitive data involved.
- Tenant or environment blast radius.
- Business service criticality.
- Detection likelihood and response readiness.
- Confidence and evidence quality.
A low-confidence critical hypothesis should trigger targeted validation, not be reported as a confirmed critical vulnerability.

## 6. Integrations to build
- **Web/API:** HTTPX/Requests, OpenAPI parser, GraphQL schema tooling, Burp Suite export/import.
- **AI evaluation:** Garak, PyRIT, custom prompt/agent benchmark harnesses.
- **Agent frameworks:** LangGraph, LangChain, CrewAI, AutoGen; framework adapters should expose state, tools, memory and checkpoints.
- **Protocols:** MCP JSON-RPC client/server test harness; A2A discovery and message-validation harness.
- **Cloud/containers:** AWS/Azure/GCP read-only inventory first; Kubernetes API/RBAC review; container and IaC scanners.
- **Code/supply chain:** Semgrep/CodeQL results, SBOM ingestion, dependency and artifact provenance checks.
- **Evidence/detection:** OpenTelemetry traces, SIEM exports, cloud audit logs, ticketing and report generation.

Tool names are integration candidates, not proof that a tool is installed, licensed or authorized. Validate versions, access and data handling before enabling adapters.

## 7. Minimum test packs
- AI app baseline: model/API fingerprint, prompt boundary, output handling, rate and error behavior.
- Agent pack: tool inventory, least privilege, argument validation, memory isolation, checkpoint integrity.
- RAG pack: ingestion provenance, ACL propagation, cross-tenant retrieval, stale/deleted content, citation integrity.
- MCP/A2A pack: discovery trust, identity binding, tool schema, transport/auth, delegation and replay.
- Cloud pack: IAM graph, workload identity, storage exposure, network reachability, secrets and Kubernetes RBAC.
- App/API pack: authentication, BOLA/IDOR, JWT configuration, schema validation, workflow invariants and tenant isolation.
- Supply-chain pack: dependency provenance, model/adapter integrity, unsafe loaders, CI/CD permissions and artifact promotion.
- Purple-team pack: event generation, telemetry verification, alert coverage, response timing and regression.

## 8. Evaluation and acceptance criteria
Score each run on:
- Asset coverage and inventory accuracy.
- Test-case relevance and correct preconditions.
- Evidence completeness and reproducibility.
- False-positive and false-negative rate.
- Scope adherence and policy-broker effectiveness.
- Tool-call correctness and argument validity.
- Prompt-injection resistance in retrieved/tool content.
- Severity calibration and confidence calibration.
- Remediation quality and retest accuracy.
- Runtime, cost, reliability and audit completeness.

Build a versioned benchmark set with known-positive, known-negative and ambiguous cases. Compare models on identical fixtures. Require human review before production rollout.

## 9. Model and multi-agent design
Use a capable reasoning model as planner/analyst, a separate code/security reviewer for independent critique, and deterministic services for authorization, parsing, policy, scoring and evidence handling. Local models can support private inference where hardware and quality permit. Do not give any model direct unrestricted credentials. Keep model selection configurable and benchmarked; avoid hard-coding one vendor.

Suggested roles:
- Planner: scope-aware test planning and task decomposition.
- Specialist workers: API, cloud, identity, RAG, MCP/A2A, ML supply chain.
- Evidence analyst: correlate observations and logs.
- Skeptic/reviewer: challenge assumptions and false positives.
- Report writer: produce stakeholder-specific outputs.
- Policy broker: deterministic, non-LLM enforcement.
The policy broker is not an agent and must not be overridden by agent consensus.

## 10. Enterprise deliverables
1. Asset and AI system inventory.
2. Architecture, data-flow, identity and trust-boundary diagrams.
3. Threat model and prioritized test plan.
4. Evidence-backed technical findings.
5. Attack-path and blast-radius analysis.
6. Executive risk summary.
7. Remediation backlog with owners and priorities.
8. Detection coverage and purple-team report.
9. Retest and regression evidence.
10. Residual-risk register and lessons learned.
