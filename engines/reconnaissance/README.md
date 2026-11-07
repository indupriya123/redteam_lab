# Cyrblu Independent Reconnaissance Engine

This service runs without `lab_redteam`, Ollama, or another engine. It owns its
configuration, credentials, SQLite database, worker queue, 23 agent definitions,
22 packaged skills, evidence, graph, API, console and reports. The existing
red-team application is a separate application, not its parent orchestrator.

This is a working initial module, **not completion of every requested live
connector or the four-engine platform**. No exploitation, credentials testing,
arbitrary tool commands, OS probes or operator-selected NSE scripts are implemented here.

## Standalone installation on Kali

Copy this directory to Kali; create a fresh environment there. Do not copy a
macOS virtual environment. Python 3.11+ and an operator-reviewed Nmap are required
for active discovery. Passive/export processing does not need Nmap.

```sh
sudo apt install python3-venv python3-pip nmap
cd engines/reconnaissance
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/recon-engine init --config-dir .recon-config
export RECON_CONFIG_DIR="$PWD/.recon-config"
export RECON_DATA_DIR="$PWD/recon-data"
export RECON_ALLOWED_CIDRS='192.168.56.0/24'
# Set this to the exact version you reviewed, as printed by nmap --version.
export RECON_NMAP_VERSION='YOUR_APPROVED_VERSION'
.venv/bin/recon-engine serve --port 8090
```

Replace the example CIDR with written customer scope. Open
`http://127.0.0.1:8090`. Copy the appropriate locally generated token into the
dashboard; tokens remain in browser memory, not local storage. The operator can
create/cancel assessments; a separate viewer token can read their publications.
Initialization refuses existing or partial configurations rather than replacing
credentials. Keep private files at 0600 and the configuration directory at 0700.

Use one backend process. One execution worker serializes engagements; up to 16
engagements can queue. Native scanner subprocesses are bounded, and cancelled
processes are terminated. Restart marks queued/running work interrupted, not
automatically reauthorized. Do not expose the dashboard through a proxy.

## Authorization and execution modes

- **PASSIVE:** customer-provided DNS, certificate, inventory and architecture
  assertions only. No target probes. Live CT/intelligence-vendor connectors are
  not implemented.
- **ACTIVE:** explicitly authorized IP/CIDR/domain targets, full TCP discovery,
  optional UDP and service probes, then bounded read-only HTTP metadata discovery.
  Every resolved DNS IP must also belong to the operator's CIDR scope.
- **AUTHENTICATED:** customer-authorized inventory/architecture exports only.
  This mode does not yet log into cloud, Kubernetes or AI services. Never put
  credentials or secrets in inventory objects.

An assessment requires a nonempty authorization reference and explicit approval.
Defaults deny all target networks. A model cannot edit scope or select commands.
Customer inventory/relationships are stored as unverified assertions/inferences
with source references, not upgraded into directly observed infrastructure.

## Capability and golden-test status

| Capability | Current execution | Validation |
|---|---|---|
| Engine/API/state, roles, queue, interruption | Standalone | Automated fixtures |
| All 22 skill packages and 23 definitions | Permissioned inventory processing | Per-skill contracts/fixtures |
| All 65,535 TCP and optional 65,535 UDP records | Batched native Nmap adapter | Complete synthetic accounting; native golden runs pending |
| Network/service fingerprints | Approved Nmap light probes | XML/profile fixtures; native certification pending |
| DNS | Approved domains and revalidated resolved IPs | Scope-expansion fixture |
| Web/OpenAPI/model-list/A2A advertisements | Bounded metadata reads | Real loopback HTTP fixture |
| MCP protocol verification | Endpoint observation only; no protocol certification | Not implemented |
| RAG, embeddings, vector databases, agent internals, AI frameworks | Customer inventory/export processing | Ingestion only; native connectors not implemented |
| Cloud, Kubernetes, identities, supply chain, telemetry | Customer inventory/export processing | Ingestion only; native connectors not implemented |
| Graph, reports, evidence integrity, signed publication | Standalone | Automated integrity/tamper fixtures |

The capabilities API deliberately reports native adapters as registered but not
certified. A framework name, route, model-list response, or successful HTTP status
does not establish exact deployed weights, model version, or a verified protocol.
No capability is certified merely because its skill is registered.

Review the installed Nmap distribution and its data/scripts as part of approval:
`-sV` can automatically run Nmap's built-in version-category NSE scripts even
without a `--script` flag. This is disclosed in scan evidence; no arbitrary
script/category selection is accepted by the engine.

## Full port discovery

Every resolved target gets records for ports 1 through 65,535, independently for
TCP and enabled UDP. Defaults: 256-port batches, at most 20 scan probes/second,
8 outstanding scan probes, one retry, 120-second Nmap host timeout and
180-second subprocess timeout. No common-port-only profile exists.

Records contain target, port, protocol, state, service, product, version,
fingerprint confidence/basis, timestamp, evidence references and assessment
status. Each completed batch produces a console line and dashboard event for
every port. This is incremental **batch-completion output**, not a claim that
Nmap exposes the instant each probe completes. Unknown, pending, interrupted,
filtered and open|filtered are preserved; only exact open states create service
candidates. Ambiguous aggregate XML states remain incomplete.

At 20 probes/second, 65,535 initial probes alone take roughly 55 minutes per
target/protocol; retries and UDP ICMP rate limiting can make runs much longer.
Service probes and HTTP metadata reads are separate from the scan-rate ceiling.
HTTP reads are serial, spaced 0.5 seconds apart, and capped at 128 per assessment.

Only identified HTTP-compatible services receive HTTP probes. Nonstandard TLS
ports use the observed service/tunnel, not just common-port guesses. HTTPS uses
certificate verification against the pinned IP; domain-only certificates can
therefore remain unverified. Domain/SNI-specific HTTPS connectors are pending.
There are no redirect, proxy-environment, insecure-TLS or authentication fallbacks.

UDP is disabled by default and requires `RECON_ENABLE_UDP=1`, separate assessment
approval, and a privileged **disposable isolated deployment**. Do not run a root
dashboard on a shared Kali host. A privilege-separated production UDP worker is
not implemented or certified. Use small batches for slow UDP labs and retain
incomplete results when host timeouts prevent completion.

Configuration variables:
`RECON_CONFIG_DIR`, `RECON_DATA_DIR`, `RECON_ALLOWED_CIDRS`,
`RECON_ALLOWED_DOMAINS`, `RECON_NMAP_VERSION`, `RECON_ENABLE_UDP`,
`RECON_MAX_TARGETS` (default 8), `RECON_BATCH_SIZE` (256),
`RECON_SCAN_RATE` (20), `RECON_MAX_PARALLELISM` (8),
`RECON_COMMAND_TIMEOUT` (180), `RECON_PORT_CONSOLE` (1).

## API and independent reporting

Every API request requires `Authorization: Bearer <recon token>`.

```text
POST /api/v1/recon/assessments
GET  /api/v1/recon/assessments
GET  /api/v1/recon/assessments/{id}
POST /api/v1/recon/assessments/{id}/cancel
GET  /api/v1/recon/assessments/{id}/events?after=0&limit=500
GET  /api/v1/recon/assessments/{id}/events/stream?after=0
GET  /api/v1/recon/assessments/{id}/assets
GET  /api/v1/recon/assessments/{id}/ports?offset=0&limit=500
GET  /api/v1/recon/assessments/{id}/ports/export
GET  /api/v1/recon/assessments/{id}/graph
GET  /api/v1/recon/assessments/{id}/evidence
GET  /api/v1/recon/assessments/{id}/report
GET  /api/v1/recon/assessments/{id}/intelligence
GET  /api/v1/recon/capabilities
```

Example passive request:

```json
{
  "title": "Customer architecture inventory",
  "mode": "PASSIVE",
  "authorization_reference": "customer-approved-scope-reference",
  "approved": true,
  "inventory": [
    {
      "name": "customer-rag-pipeline",
      "kind": "rag",
      "source_reference": "customer-architecture-export",
      "attributes": {"framework": "customer-declared"}
    }
  ]
}
```

Example active request:

```json
{
  "title": "Authorized full-range discovery",
  "mode": "ACTIVE",
  "authorization_reference": "customer-approved-scope-reference",
  "approved": true,
  "targets": ["192.168.56.21"],
  "fingerprint_services": true,
  "udp": false
}
```

The Markdown report includes every required inventory section, graph links,
confidence, unknowns, limitations and next steps. Missing sections say
unobserved/unassessed, never secure. The complete port inventory is a paginated
API and terminal-state JSONL download, not an enormous inline Markdown table.
The JSONL descriptor is bound into the signed package by SHA256.

Evidence metadata and extracted observations are retained locally. Raw Nmap XML,
HTTP response bodies and cookies are not retained. Publication validates evidence
hashes and references before signing; these local records are not immutable or
an external timestamped forensic archive.

## Versioned engine-to-engine publication

Terminal assessments publish contract version 1.0 signed with Ed25519. Graph and
evidence references are included. Full port data is represented by a JSONL URL,
count and digest; consumers must verify that digest before trusting downloaded
port rows. Pin the public key out of band, never trust a key embedded in a package.

```sh
.venv/bin/recon-engine verify recon-intelligence.json \
  --trusted-key .recon-config/signing.pub
```

The separate red-team application's integration is opt-in:

```sh
export LAB_RECON_URL='http://127.0.0.1:8090'
export LAB_RECON_TOKEN_FILE='/absolute/path/to/recon/.recon-config/viewer.token'
export LAB_RECON_PUBLIC_KEY='/absolute/path/to/pinned/signing.pub'
```

Its `/api/recon/intelligence/{id}` endpoint consumes and verifies only this
versioned API publication; it never imports reconnaissance modules or reads the
recon database. Consumption does **not** start an attack or inherit authorization.
Automatic assessment planning and engines 3/4 remain future independent modules.

## Independently installed skills and tests

Each `skills/<id>` contains a package manifest and declarative permission profile.
The executable framework is the independently installed reconnaissance runtime;
a skill package is not an unrestricted standalone shell tool.

```sh
.venv/bin/python -m pip install ./skills/mcp_discovery
.venv/bin/python -m cyrblu_recon.skills.check skills/mcp_discovery/skill.json
.venv/bin/python -m pytest tests -q
.venv/bin/python -m pytest tests -q -k mcp_discovery
```

Golden tests cover every agent/skill's inventory permission and input limits,
full TCP/UDP record accounting, deterministic open-port precision/recall,
confidence, real loopback HTTP, cancellation, recovery, evidence integrity and
signature tampering. Synthetic accounting metrics do not certify native Nmap.

`tests/lab` supplies an isolated container fixture with TCP 8001, UDP 9001,
synthetic web/API/model/A2A metadata, and separately labeled architecture exports.
The exports are **not** running Kubernetes/RAG/vector/MCP integrations.
The container recipe and native tests still need execution on Kali; they were
not certified on the development host.

On an authorized isolated Linux lab with Docker installed:

```sh
docker compose -f tests/lab/compose.yaml up -d --build
export RECON_RUN_NATIVE_GOLDEN=1
export RECON_GOLDEN_TARGET='172.30.77.21'
export RECON_GOLDEN_TCP_PORTS='8001'
export RECON_NMAP_VERSION='YOUR_APPROVED_VERSION'
.venv/bin/python -m pytest tests/test_golden.py -q -k native_full_tcp
```

The optional privileged UDP golden test also requires
`RECON_RUN_NATIVE_UDP_GOLDEN=1` and `RECON_GOLDEN_UDP_PORTS=9001`.
It evaluates all TCP and UDP ports and can take many hours. Native precision,
recall and completeness must pass before declaring those capabilities certified.
