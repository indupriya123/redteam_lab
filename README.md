# Lab Red Team

Local web dashboard and Python backend for **allowlisted, non-destructive lab
assessment** and synthetic vulnerable/fixed demonstrations. This is an initial
lab prototype, not an autonomous exploitation platform or a production service.

## Kali Linux setup

Requires Python 3.11 or newer. Copy this project, including `references/AI-Agent`,
to Kali. Do not copy the macOS `.venv`; create a new virtual environment on Kali.

```sh
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
.venv/bin/python -m pip install -e .
export LAB_ALLOWED_CIDRS='192.168.56.0/24'
.venv/bin/python -m lab_redteam
```

Replace the example range with your authorized lab scope. Open
`http://127.0.0.1:8765` in the Kali browser, enter explicit IPs and HTTP service
ports, create an engagement, review its scope, and approve execution. Download
the resulting Markdown/JSON report. No root privileges are needed for assessment
or serving the dashboard. Do not use system-wide `sudo pip`.

For a different dashboard port: `.venv/bin/python -m lab_redteam --port 8766`.
The launcher binds loopback and uses exactly one backend process. The browser UI
is bundled locally; Node.js, a frontend build, and internet access are not needed
at runtime. Dependency installation and obtaining local model weights may need
internet access beforehand.

Ollama is optional. Install it on Kali using its official Linux instructions,
disable cloud features in the Ollama service, and select an already installed
local model. Hardware/GPU capacity determines inference throughput.

## Run

From this folder:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m lab_redteam
```

Open `http://127.0.0.1:8765`. Synthetic mode needs no target IPs or model.
Keep the `references/AI-Agent` folder in place: its structured records are loaded
at startup. Do not expose the dashboard through a proxy or public interface.

To enable network checks, the operator must set exact authorized lab ranges:

```sh
export LAB_ALLOWED_CIDRS='192.168.56.0/24'
.venv/bin/python -m lab_redteam
```

Replace the example with your actual written scope. The dashboard then accepts
explicit IPs inside those ranges, not hostnames or CIDR expansion. Public,
link-local, multicast and unspecified targets are blocked. Operator scope is
not editable by the model or the dashboard.

## Implemented execution

- Planner selects only built-in adapters; objectives are context, never commands.
- Deterministic policy broker validates scope, authorization, request budget and approval.
- Discovery specialist performs HTTP `HEAD /` on at most eight explicit IPs and
  four ports each. One request at a time per run, with globally paced request starts.
- Optional **explicitly approved** `GET /` fallback runs only after HEAD 405/501.
  It inspects response headers without reading/storing the body and does not
  follow redirects. Authorization is part of the immutable engagement;
  previously approved runs do not acquire new permissions.
- HTTP hardening checks record missing response headers where applicable.
  These are low-severity observations, not confirmed exploits.
- Simulation specialist compares vulnerable/fixed in-memory RAG tenant filtering,
  misleading tool capabilities, and skipped workflow gates. No external actions.
- Evidence reviewer checks finding references; optional local model critiques
  the report without tools or authority. Reporter exports Markdown and JSON.
- Operator stop cancels execution; restart marks incomplete runs interrupted.

Up to 32 approved engagements can queue, with two local workers and one Ollama
review at a time. Each engagement has separate scope, evidence and reports.
Network request starts are globally paced at no more than two per second.
Network adapters share a serialized execution gate across engagements; a Nuclei
process holds that gate until completion, followed by the pacing delay.
Use a single backend process: multiple Uvicorn workers would bypass in-process
queue/rate controls. Queued work is marked interrupted after a server restart
rather than automatically re-authorized.

Network mode does not submit prompts, collect response bodies, follow redirects,
disable TLS verification, expand networks, use credentials, or execute commands.
HTTPS is used on ports 443 and 8443; other selected ports are treated as HTTP.
HEAD-only observations need further browser/GET verification where indicated.
HEAD-only behavior remains the default. A fallback or scanner selection limits
the engagement to 16 IP/port pairs. The GET fallback and HEAD-only Nuclei adapter
are mutually exclusive for a given response, so both options still fit that budget.

## Local model

Run Ollama locally and enter an **already installed** model name in the engagement
form. The application only contacts Ollama at `127.0.0.1:11434`; it neither downloads
models nor selects cloud providers. Before sending report context, `/api/show`
must confirm local model parameter metadata and no remote-host/model designation.
Requests disable environment proxies.
If Ollama is unavailable or the model fails, the report explicitly records the
review failure. Deterministic execution does not require an LLM.

Disable cloud features in the Ollama service itself (`OLLAMA_NO_CLOUD=1` in
that service's environment, then restart it) and enforce host egress restrictions
where confidentiality requires them. Contacting a local API alone cannot
guarantee the service does not forward data. Unrecognized model metadata is
rejected rather than assumed local.

The model advisory is unverified. It cannot create confirmed findings, authorize
operations, expand scope, or select arbitrary tools. This is a bounded specialist
workflow with an optional LLM reviewer, not multiple autonomous offensive LLMs.

## Catalogue and reports

Loads all 81 base technique records, 30 overlapping enterprise extensions, 12 skill
domains, and 25 enterprise capabilities from the supplied references. Each
technique retains source location and is marked **reference only**. Enterprise
records receive unique IDs while retaining the source's repeated `ENT-1` ID.
The tool-catalogue Word document is reference material, not executable adapters.

## Staged scanner integrations

`/api/tools` and the dashboard register all 30 tools from the tool catalogue plus Nmap,
including installation detection, domain, adapter status, and limitations.
**Nuclei and Nmap have bounded executable external-tool adapters.** Registering
Semgrep, Gitleaks, Trivy, model scanners, or benchmark frameworks does not mean
they ran. Source/artifact/cloud checks require additional authorized inputs;
an IP address alone cannot establish their coverage.

For Nuclei, install and review an appropriate release on Kali and configure the
exact installed version as `LAB_NUCLEI_VERSION` before starting the backend.
The adapter rechecks the version at execution and rejects mismatches. The first
command profile uses Nuclei 2/3 flags; actual validation on this development
machine used its preinstalled 2.9.15 executable, not a Kali installation.
Do not downgrade Kali to that old release simply to match the development host.
Validate your current approved release against the bundled template.

Select the Nuclei checkbox in a network engagement. It runs only the bundled
HEAD-only missing-nosniff template against a successful plain HTTP baseline.
HTTPS scanner execution is deliberately skipped; verified TLS inspection remains
in the built-in adapter. Arbitrary templates, CLI arguments, configuration,
credentials, redirects, external callbacks, and update checks are not enabled.
Version/binary/template hashes and sanitized alert metadata are retained.
Raw request/response pairs are omitted.

The correlation specialist attaches scanner evidence to the matching HTTP
observation instead of creating a duplicate finding. Disagreement is recorded
as a validation gap, and no scanner match is not a pass. Selecting Nuclei reduces
the maximum IP/port pairs to 16 so planned target requests remain at most 32.
Nuclei subprocesses are serialized, rate-limited to one request per second, and
bounded by output limits and a 20-second timeout. They are killed on cancellation.

## Nmap discovery skill

On Kali, install Nmap if needed (`sudo apt install nmap`), check `nmap --version`,
and set `LAB_NMAP_VERSION` to the exact operator-approved version printed there.
Restart the backend, select **Nmap discovery**, and enter your approved IPs and
port list. The common-port button is only a form convenience; it does not authorize
or execute anything.

Nmap performs an unprivileged TCP-connect scan (`-sT`), with DNS and separate
host-discovery probes disabled. It accepts at most 64 explicitly listed ports
and 128 total IP/port pairs. It does not scan all 65,535 ports, invoke NSE scripts,
perform version/OS probes, test credentials, or accept arbitrary flags.
IPv4 and IPv6 targets need separate engagements. Its configured scan rate is two
probes per second, one outstanding probe, zero retries, 45-second per-host timeout,
and 180-second process timeout. Kernel/network behavior and missed responses mean
this is not an exhaustive reachability guarantee.

The parser checks scanner/version, scan type, protocol, scanned port set, and
each reported target/port against approved scope. Only exact `open` states become
follow-up candidates; `open|filtered` does not. The policy broker validates those
candidates again. Evidence includes open-port records and binary/XML hashes;
raw XML, MAC addresses and hostnames are not retained.

Confirmed open ports are automatically fed to the existing bounded HTTP/TLS
adapters. Follow-up requests across all hosts share the 32-request budget;
overflow ports are recorded as explicit gaps. Closed/unreported ports do not
become security findings. Service protocol remains unverified until a valid
application response is observed; non-HTTP services have no exploitation adapters.
This is scoped discovery and validation, not automated compromise.

Reports include authorization, scope, plan, findings, severity/confidence,
synthetic versus observed status, evidence hashes, recommendations, retest criteria,
coverage gaps and agent audit history. Reports never equate zero findings with a
pass or partial evidence with compromise. Retests are new engagements requiring
new approval; automatic remediation is not implemented.

Workflow status and assessment verdict are separate. A completed run with no
applicable successful HTTP/TLS checks is **inconclusive**, not a pass. Reports and
the dashboard show HTTP responders versus endpoints with applicable hardening
checks. Successful limited checks produce **limited_coverage**, never a blanket
security pass. Verdicts are derived on read for historical runs too, without
rewriting their evidence or audit hashes. Connection failures retain structured
OS/TLS diagnostics where available; an ambiguous error is not attributed to a
firewall or routing problem without evidence.

SQLite snapshots persist under `data/`. Protect that directory with host access
controls and set your own retention policy. Evidence/audit hashes are not
signatures and the database is not immutable. Avoid entering secrets in objectives
or authorization references. All browser-rendered results use text rather than HTML.
The backend uses a process lock on its data directory; this implementation targets
macOS/Linux, not Windows.
Set `LAB_DATA_DIR` to override the storage directory.

## Validate

```sh
.venv/bin/python -m pytest -q
```
