import asyncio
import logging
import uuid

import httpx

from ..config.settings import Settings
from ..database.store import Store, timestamp
from ..intelligence.correlation import correlate, http_intelligence
from ..schemas.models import Assessment
from ..skills.registry import Registry
from ..tools.dns import resolve
from ..tools.http import HTTPWorker, PATHS
from ..tools.nmap import NmapWorker

LOG = logging.getLogger("cyrblu.recon")


class Engine:
    def __init__(self, settings: Settings, store: Store):
        self.settings, self.store = settings, store
        self.registry = Registry()
        self.nmap, self.http = NmapWorker(settings), HTTPWorker(settings)
        self.tasks: dict[str, asyncio.Task] = {}
        self.worker_slot = asyncio.Semaphore(1)
        self.agent_slots = asyncio.Semaphore(4)

    def create(self, spec: Assessment) -> dict:
        self.settings.validate(spec)
        self.tasks = {key: task for key, task in self.tasks.items() if not task.done()}
        if len(self.tasks) >= 16:
            raise ValueError("Reconnaissance queue is full")
        identifier = str(uuid.uuid4())
        document = {"id": identifier, "created_at": timestamp(), "status": "queued",
                    "spec": spec.model_dump(), "resolved_targets": [], "agent_states": {},
                    "limitations": [], "http_requests": 0}
        self.store.save(document)
        self.store.event(identifier, "recon_orchestrator", "Independent engagement authorized and queued")
        self.tasks[identifier] = asyncio.create_task(self.execute(document, spec))
        return document

    async def cancel(self, identifier: str) -> dict:
        document = self.store.assessment(identifier)
        task = self.tasks.get(identifier)
        if document["status"] not in {"queued", "running"} or task is None:
            raise ValueError("Assessment is not active")
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        document = self.store.assessment(identifier)
        if document["status"] in {"queued", "running"}:
            document["status"] = "cancelled"
            document["limitations"].append("Cancelled before worker acquisition; discovery was not performed.")
            self.store.interrupt(identifier, "cancelled")
            self.store.save(document)
        return document

    async def shutdown(self):
        for identifier, task in list(self.tasks.items()):
            if not task.done():
                await self.cancel(identifier)

    async def inventory_agent(self, skill_id: str, document: dict, spec: Assessment):
        skill = self.registry.skills[skill_id]
        async with self.agent_slots:
            document["agent_states"][skill.agent] = {"status": "running", "skill": skill_id}
            count = self.registry.ingest(skill_id, document["id"], spec.mode, spec.inventory, self.store)
            document["agent_states"][skill.agent] = {
                "status": "completed" if count else "not_assessed", "skill": skill_id, "inventory_items": count,
                "basis": "supplied_intelligence_only" if count else "no_matching_inventory_input",
            }
            await asyncio.sleep(0)

    async def execute(self, document: dict, spec: Assessment):
        identifier = document["id"]
        try:
            async with self.worker_slot:
                document["status"] = "running"
                self.store.save(document)
                await asyncio.gather(*(self.inventory_agent(skill, document, spec) for skill in self.registry.skills))
                if spec.mode == "ACTIVE":
                    await self.active(document, spec)
                elif spec.mode == "AUTHENTICATED":
                    document["limitations"].append("Authenticated mode ingests customer-authorized exports; live cloud/Kubernetes credential connectors are not implemented.")
                else:
                    document["limitations"].append("Passive mode uses supplied intelligence; live CT/public-intelligence vendor connectors are not implemented.")
                correlate(identifier, spec.mode, spec.relationships, self.store)
                document["agent_states"]["correlation"] = {"status": "completed"}
                document["limitations"].extend([
                    "Unknown or untested architecture is not absent architecture; no vulnerability or compromise is claimed.",
                    "Exact model identity/version is not established by endpoint names or provider metadata.",
                    "Local evidence hashes are not an immutable evidence store.",
                    "Live RAG, vector, memory, identity, cloud and Kubernetes connectors require supplied exports or future validated adapters.",
                ])
                document["status"] = "completed"
                self.store.event(identifier, "recon_reporter", "Independent reconnaissance intelligence is ready")
        except asyncio.CancelledError:
            document["status"] = "cancelled"
            document["limitations"].append("Execution cancelled; unscanned ports remain explicitly incomplete.")
            self.store.interrupt(identifier, "cancelled")
            self.store.event(identifier, "recon_orchestrator", "Assessment cancelled; no automatic restart")
        except Exception as exc:
            LOG.exception("Reconnaissance failed: %s", identifier)
            document["status"] = "failed"
            document["limitations"].append(f"Execution failed: {type(exc).__name__}: {exc}")
            self.store.interrupt(identifier, "failed")
            self.store.event(identifier, "recon_orchestrator", "Execution failed; completed evidence retained")
        finally:
            for state in document["agent_states"].values():
                if state["status"] == "running":
                    state["status"] = document["status"] if document["status"] != "completed" else "incomplete"
            document["finished_at"] = timestamp()
            self.store.save(document)

    async def active(self, document: dict, spec: Assessment):
        identifier = document["id"]
        self.registry.authorize("dns_intelligence", "dns_intelligence", "dns", spec.mode)
        document["agent_states"]["dns_intelligence"] = {"status": "running", "skill": "dns_intelligence"}
        targets, dns = await resolve(spec.targets, self.settings)
        document["agent_states"]["dns_intelligence"] = {
            "status": "completed" if dns else "not_assessed", "skill": "dns_intelligence",
            "basis": "authorized_domain_resolution" if dns else "explicit_IP_scope_no_DNS_needed",
        }
        if not targets:
            raise ValueError("Scope resolved to no executable targets")
        document["resolved_targets"] = targets
        for observation in dns:
            ref = self.store.capture(identifier, "dns_adapter", spec.mode, observation)
            domain = self.store.asset(identifier, "domain", observation["domain"], ref)
            for address in observation["addresses"]:
                ip = self.store.asset(identifier, "ip", address, ref)
                self.store.edge(identifier, domain, ip, "resolves_to", ref, False, 1)
        self.registry.authorize("full_port_discovery", "port_discovery", "nmap", spec.mode)
        self.registry.authorize("network_discovery", "network_discovery", "nmap", spec.mode)
        document["agent_states"]["port_discovery"] = {"status": "running", "skill": "full_port_discovery"}
        if spec.fingerprint_services:
            self.registry.authorize("service_fingerprinting", "service_fingerprinting", "nmap", spec.mode)
            document["agent_states"]["service_fingerprinting"] = {"status": "running", "skill": "service_fingerprinting"}
        protocols = ["tcp", "udp"] if spec.udp else ["tcp"]
        self.store.seed_ports(identifier, targets, protocols)
        self.store.save(document)
        self.store.event(identifier, "port_discovery", "Full-range port records initialized", {
            "targets": targets, "protocols": protocols, "ports_per_target_protocol": 65535,
        })
        for target in targets:
            for protocol in protocols:
                for start in range(1, 65536, self.settings.batch_size):
                    ports = list(range(start, min(65536, start + self.settings.batch_size)))
                    self.store.event(identifier, "port_discovery", "Approved batch starting", {
                        "target": target, "protocol": protocol, "port_range": [ports[0], ports[-1]],
                    })
                    records, observation = await self.nmap.batch(target, protocol, ports, spec.fingerprint_services)
                    ref = self.store.capture(identifier, "nmap_adapter", spec.mode, observation)
                    for record in records:
                        record["evidence_refs"] = [ref]
                    self.store.ports_batch(identifier, records)
                    if self.settings.print_ports:
                        for record in records:
                            LOG.info("PORT %s %s/%s %s %s", target, record["port"], protocol, record["state"], record["service"])
                    if any(record["state"] in {"open", "closed"} for record in records):
                        self.store.asset(identifier, "ip", target, ref, {"basis": "Nmap_port_response"})
                    for record in records:
                        if record["state"] == "open":
                            ip = self.store.asset(identifier, "ip", target, ref)
                            name = f"{target}:{record['port']}/{protocol}"
                            port_node = self.store.asset(identifier, "port", name, ref, {
                                "port": record["port"], "protocol": protocol, "state": record["state"]})
                            probed = record.get("fingerprint_basis") == "service_probe"
                            service = self.store.asset(identifier, "service", name, ref, record,
                                                       inferred=not probed, confidence=record["fingerprint_confidence"])
                            self.store.edge(identifier, ip, port_node, "exposes", ref, False, 1)
                            self.store.edge(identifier, port_node, service, "uses", ref, not probed,
                                            record["fingerprint_confidence"])
                            if protocol == "tcp" and record["service"] in {"http", "https", "ssl/http", "http-alt", "http-proxy"}:
                                await self.web(document, record)
                    self.store.save(document)
                    await asyncio.sleep(0)
        coverage = self.store.coverage(identifier)
        if coverage["uncompleted_ports"]:
            document["limitations"].append("Some Nmap batches returned incomplete/ambiguous port records; full coverage was not achieved.")
        document["agent_states"]["port_discovery"] = {"status": "completed" if not coverage["uncompleted_ports"] else "incomplete",
                                                     "coverage": coverage}
        document["agent_states"]["network_discovery"] = {
            "status": "completed", "basis": "scoped_Nmap_evidence_not_general_network_enumeration"}
        if spec.fingerprint_services:
            document["agent_states"]["service_fingerprinting"] = {
                "status": "completed" if not coverage["uncompleted_ports"] else "incomplete",
                "basis": "approved_light_service_probes_unknown_fingerprints_retained",
            }
        self.store.save(document)

    async def web(self, document: dict, port: dict):
        self.registry.authorize("web_fingerprinting", "web_fingerprinting", "http", "ACTIVE")
        identifier = document["id"]
        for path in PATHS:
            if document["http_requests"] >= 128:
                if "HTTP discovery budget exhausted; remaining services/endpoints are unassessed." not in document["limitations"]:
                    document["limitations"].append("HTTP discovery budget exhausted; remaining services/endpoints are unassessed.")
                return
            document["http_requests"] += 1
            skill_id = {
                "/openapi.json": "api_discovery", "/v1/models": "llm_fingerprinting",
                "/api/tags": "llm_fingerprinting", "/.well-known/agent-card.json": "a2a_discovery",
                "/.well-known/agent.json": "a2a_discovery", "/mcp": "mcp_discovery",
            }.get(path, "web_fingerprinting")
            skill = self.registry.skills[skill_id]
            self.registry.authorize(skill_id, skill.agent, "http", "ACTIVE")
            state = document["agent_states"][skill.agent]
            state["status"] = "running"
            try:
                tls = port["service"] in {"https", "ssl/http"} or port.get("tunnel") == "ssl"
                observation = await self.http.observe(port["target"], port["port"], path, tls=tls)
            except (httpx.HTTPError, TimeoutError, ValueError) as exc:
                self.store.capture(identifier, "http_adapter", "ACTIVE", {
                    "target": port["target"], "port": port["port"], "path": path,
                    "outcome": "unverified", "error_type": type(exc).__name__,
                })
                state["status"] = "incomplete"
                state["basis"] = "endpoint_unverified"
                self.store.event(identifier, skill.agent, "HTTP discovery unavailable", {"port": port["port"], "error": type(exc).__name__})
                return
            ref = self.store.capture(identifier, "http_adapter", "ACTIVE", observation)
            http_intelligence(identifier, observation, ref, self.store)
            state.update(status="completed", basis="endpoint_observation_not_protocol_or_architecture_certification")
            state["endpoint_observations"] = state.get("endpoint_observations", 0) + 1
            self.store.event(identifier, skill.agent, "Endpoint observed", {
                "url": observation["url"], "status": observation["status"],
            })
            await asyncio.sleep(0.5)
