# Adaptive reconnaissance development and operations

## What changed

The existing standalone engine is extended, not replaced. `tools/openapi.py`
is an independently callable JSON/YAML/Swagger/OpenAPI analyser.
`tools/api_recon.py` coordinates scoped metadata recursion.
`tools/exports.py` ingests customer BloodHound and SBOM exports.
`intelligence/planning.py` generates confidence-weighted next-action proposals
from configurable trusted rules. Proposals never become automatic attack/tool
execution, and declared permissions are not validated permissions.

SQLite remains the existing single-worker local store. The additive migration
`database/migrations/001-domain-intelligence.sql` adds durable categorized
intelligence and tool execution records without replacing old assessments.
Migration versions are recorded in `schema_migrations`.

## Independent domain selection

Supported domain selectors are `inventory`, `network`, `web`, `api`, `identity`,
and `supply_chain`. Network execution requires the existing Nmap policy.
`identity` and `supply_chain` currently mean customer-export analysis, not live
credentialed services. `web`/`api` accept explicit URL seeds and do not require
Nmap. Default selectors preserve the previous assessment behavior.

Each URL authorizes its exact HTTP(S) scheme/hostname/port origin, not other
ports, DNS neighbours or advertised server origins. Operator CIDR/domain
allowlists and global `RECON_DENIED_CIDRS` / `RECON_DENIED_DOMAINS` still apply.
Assessment exclusions accept IPs, CIDRs, domains and URL prefixes. Excluded,
credential-bearing, query-bearing, ambiguous/double-encoded and third-party
URLs are refused. All resolved addresses are checked; requests connect to a
pinned IP while preserving Host and TLS SNI. Certificate verification stays on.

## API-only example

```json
{
  "title": "Authorized API inventory",
  "mode": "ACTIVE",
  "domains": ["web", "api"],
  "urls": ["http://192.168.56.21:8001/"],
  "authorization_reference": "written-customer-scope",
  "approved": true,
  "safe_get_paths": ["/public-metadata"],
  "exclusions": ["http://192.168.56.21:8001/private"]
}
```

Use only paths separately approved as non-destructive. Discovery follows
documentation/schema/JavaScript metadata links and approved redirects within
the authorized origins, never arbitrary business operations. POST/PUT/PATCH/
DELETE/TRACE are documented but not executed. Required path/query values are
not guessed. An observed 200 response is not validated authorization or a pass.

The combined HTTP budget is 128 requests per assessment, serially paced at
0.5 seconds. Recursive depth is bounded at 4, document count at 32, body size
at 1 MiB, automatically selected HTTP origins at 16. Schema resolution and
operation inventories are bounded. Budget/ref/parser failures are recorded as
incomplete; unknown operations behind a failed document are explicitly unknown.
Reference expansion is capped at 50,000 nodes and 4 MiB of expanded content.
Signed API publications refuse inventories above 10,000 operations rather than
silently publishing a partial inventory. JSON reports identify their record
limits; paginated intelligence/execution endpoints retain remaining records.

## Offline source documents

```json
{
  "title": "Customer export analysis",
  "mode": "AUTHENTICATED",
  "domains": ["api", "identity", "supply_chain"],
  "authorization_reference": "customer-export-authorization",
  "approved": true,
  "documents": [
    {
      "format": "openapi",
      "name": "schema.json",
      "source_reference": "customer architecture export",
      "content": {
        "openapi": "3.1.0",
        "info": {"title": "Example", "version": "1"},
        "paths": {"/metadata": {"get": {"responses": {"200": {"description": "OK"}}}}}
      }
    }
  ]
}
```

Formats: `openapi`, `bloodhound`, `cyclonedx`, `spdx`. OpenAPI content can be a
JSON object or YAML string. Supplied documents share logical base
`https://supplied.invalid/<name>` so separately supplied reference files can be
resolved offline; this is a document identifier, not a probed host.

BloodHound supports `data` objects with `ObjectIdentifier`, `Properties`,
`Aces` and `Members`. Known principals/member nodes produce source-asserted
relationships. Missing objects are not invented. CycloneDX/SPDX support basic
package/version inventory; CycloneDX dependencies map known component refs.
This is not complete BloodHound CE analysis, live LDAP/AD CS enumeration,
package installation verification, or CVE attribution.

Raw documents are not persisted in engagement configuration. Evidence retains
hashes and normalized metadata. Examples/defaults and known credential-bearing
fields are redacted; this is not a general free-text DLP certification.
Do not upload secrets, tickets, password hashes, sensitive business responses
or unrestricted archives.

## Completeness and interfaces

New authenticated endpoints:

```text
GET /api/v1/recon/tools
GET /api/v1/recon/assessments/{id}/executions
GET /api/v1/recon/assessments/{id}/intelligence/{category}?offset=0&limit=500
GET /api/v1/recon/assessments/{id}/report?format=json
GET /api/v1/recon/assessments/{id}/report?format=html
```

Categories: `api_specification`, `api_operation`, `api_server`, `api_issue`,
`web_route`, `api_route_comparison`, `ad_object`, `supply_chain_component`,
`assessment_plan`. The API response includes per-category status counts.
FastAPI's `/docs` exposes validated request schemas; credentials remain required
for execution and intelligence reads.

API completeness separates operations analysed from validation performed.
Every supported documented method is a separate record, including malformed
operations recorded as incomplete. Local/external references are resolved only
when their documents are available and authorized. Circular schema references
are represented without infinite expansion. Additional unapproved servers are
recorded, not scanned. Failed specifications can leave operation counts unknown.
100% runtime API security coverage is never asserted.

Signed contract 1.0 remains backward compatible: normalized API operations are
included in `applications` with `kind: api_operation`; API/domain coverage and
next-action proposals are in `coverage`. All source evidence references remain
signed. The red-team consumer still cannot access execution internals or inherit
authorization from a publication.

## Deployment and troubleshooting

Use `bash install.sh`, then the existing README credential initialization and
loopback-only launcher. Review `config/environment.example`. Runtime can be
offline after installing packages; public-intelligence connectors are not
implemented. Do not expose a root worker/dashboard on a shared host.

| Symptom | Meaning / action |
|---|---|
| Nmap unavailable/version rejected | Network domain remains incomplete; API-only URL discovery can run without it |
| URL origin outside scope | Explicitly authorize a separate origin in a new assessment, never relax scope based on links |
| TLS verification failure | Supply properly trusted customer certificates; no insecure retry |
| Document/reference failure | Review the persisted API issue and provide the missing authorized source document |
| Incomplete operation analysis | Resolve schema/parameter errors or reduce approved inventory size; no coverage pass |
| GET profile not executed | Only explicit non-destructive paths without guessed parameters may run |
| Native golden test skipped | No certification; requires installed tools and explicitly authorized isolated lab |
| PDF requested | Renderer is not implemented; use generated HTML/JSON/Markdown |

The fixture Docker recipe remains available but unexecuted here: Docker and
native Nmap are unavailable. A Windows/AD CS lab, customer cloud accounts,
Kubernetes access, and live AI stacks were not provided.

## Testing and completion

Run `python -m pytest tests -q` from the engine package, or both engine/root
tests from the repository workspace. Tests cover real loopback API discovery,
JSON/YAML/Swagger versions, methods, security overrides, recursive/local/external
references, circular schemas, conservative GET profiles, denied boundaries,
redaction, persistent history, migrations and failure isolation.

See `completion-matrix.md` for measured results and explicit remaining work.

Generate reproducible JSON/HTML reports and observed request results with
`python examples/generate_reports.py examples/generated`. This starts and stops
its own loopback-only synthetic HTTP fixture; it neither scans native ports nor
certifies AD/cloud/Kubernetes/AI infrastructure.
