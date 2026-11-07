import asyncio
import copy
import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from fastapi.testclient import TestClient

from cyrblu_recon.agents.definitions import NAMES, SKILLS, definitions
from cyrblu_recon.app import create_app
from cyrblu_recon.config.settings import Settings, initialize
from cyrblu_recon.database.store import timestamp
from cyrblu_recon.intelligence.correlation import correlate, http_intelligence
from cyrblu_recon.intelligence.signing import publish, verify
from cyrblu_recon.orchestrator.engine import Engine
from cyrblu_recon.reporting.report import canonical, markdown, payload, port_lines
from cyrblu_recon.schemas.models import Assessment, InventoryItem, Relationship
from cyrblu_recon.skills.registry import Registry
from cyrblu_recon.tools.dns import resolve
from cyrblu_recon.tools.http import HTTPWorker
from cyrblu_recon.tools.nmap import NmapWorker, parse_batch, port_set

REGISTRY = Registry()


def spec(**values):
    return Assessment(title="Golden fixture", authorization_reference="synthetic authorized lab",
                      approved=True, inventory=[InventoryItem(kind="model", name="synthetic-model", source_reference="fixture")],
                      **values)


def record(identifier="fixture", **values):
    return {"id": identifier, "created_at": timestamp(), "status": "completed", "spec": spec().model_dump(),
            "limitations": [], "agent_states": {}, **values}


def xml(start=1, end=3, protocol="tcp", host="127.0.0.1", version="7.95", explicit="",
        extras='<extraports state="closed" count="3"/>', finished="success"):
    return (f'<nmaprun scanner="nmap" version="{version}"><scaninfo type="{"connect" if protocol == "tcp" else "udp"}" '
            f'protocol="{protocol}" services="{start}-{end}"/>'
            f'<host><status state="up"/><address addr="{host}" addrtype="ipv4"/><ports>{extras}{explicit}</ports></host>'
            f'<runstats><finished exit="{finished}"/></runstats></nmaprun>').encode()


@pytest.mark.parametrize("skill_id", SKILLS)
def test_each_skill_inventory_and_permissions(skill_id, store):
    skill = REGISTRY.skills[skill_id]
    item = InventoryItem(kind=skill.kinds[0], name=f"golden-{skill_id}", source_reference="synthetic inventory")
    for mode in skill.modes:
        assert REGISTRY.ingest(skill_id, mode, mode, [item], store) == 1
        asset = store.assets(mode)[0]
        assert asset["inferred"] and asset["confidence"] == 0.7
        assert store.evidence(mode)[0]["observation"]["basis"] == "customer_supplied_assertion_not_live_validation"
    with pytest.raises(ValueError, match="permission denied"):
        REGISTRY.authorize(skill_id, "different-agent", "inventory", "PASSIVE")
    with pytest.raises(ValueError):
        REGISTRY.authorize(skill_id, skill.agent, "http", "PASSIVE")
    with pytest.raises(ValueError):
        REGISTRY.ingest(skill_id, "overflow", "PASSIVE", [item] * (skill.max_items + 1), store)


def test_agent_identity_mapping():
    agents = definitions(REGISTRY)
    assert len(agents) == 23
    assert [(item["name"], item["skills"][0]) for item in agents[:-1]] == list(zip(NAMES[:-1], SKILLS))
    assert len({item["id"] for item in agents}) == 23


def test_initialization_and_role_policy(settings):
    old = (settings.config_dir / "operator.token").read_bytes()
    with pytest.raises(ValueError):
        initialize(settings.config_dir)
    assert (settings.config_dir / "operator.token").read_bytes() == old
    assert settings.role(old.decode()) == "operator"
    assert settings.role("not-a-token") is None
    assert settings.role((settings.config_dir / "viewer.token").read_text()) == "viewer"
    settings.validate(spec())
    with pytest.raises(ValueError):
        settings.validate(spec(mode="ACTIVE", targets=["192.0.2.1"]))
    with pytest.raises(ValueError):
        settings.validate(spec(targets=["127.0.0.1"]))
    with pytest.raises(ValueError):
        settings.validate(spec(fingerprint_services=True))
    with pytest.raises(ValueError):
        settings.validate(spec(mode="ACTIVE", targets=["127.0.0.0/8"]))
    with pytest.raises(ValueError):
        settings.validate(Assessment(title="No approval", authorization_reference="fixture", approved=False))
    with pytest.raises(ValueError):
        settings.validate(Assessment(title="Secret", authorization_reference="fixture", approved=True,
                                     inventory=[InventoryItem(kind="identity", name="fixture", source_reference="fixture",
                                                              attributes={"api_key": "redacted-fixture"})]))


def test_observed_and_inferred_graph_evidence(store):
    ref = store.capture("fixture", "fixture", "PASSIVE", {"test": True})
    store.asset("fixture", "agent", "agent", ref)
    store.asset("fixture", "tool", "tool", ref, {"owner": "observed"})
    store.asset("fixture", "tool", "tool", ref, {"owner": "unverified"}, inferred=True, confidence=0.6)
    correlate("fixture", "PASSIVE", [Relationship(source="agent", target="tool", relation="uses",
                                                inferred=True, confidence=0.8, source_reference="fixture")], store)
    graph = store.graph("fixture")
    assert len(graph["inferred_edges"]) == 1 and not graph["observed_edges"]
    tool = next(item for item in graph["nodes"] if item["kind"] == "tool")
    assert tool["attributes"]["owner"] == "observed" and not tool["inferred"]
    with pytest.raises(ValueError, match="ambiguous"):
        correlate("fixture", "PASSIVE", [Relationship(source="missing", target="tool", relation="uses", source_reference="fixture")], store)


def test_recovery_beyond_first_hundred_assessments(store):
    store.save(record("old-active", status="running"))
    for index in range(101):
        store.save(record(str(index)))
    store.recover()
    assert store.assessment("old-active")["status"] == "interrupted"


def test_complete_tcp_udp_inventory_and_interrupt(store):
    store.seed_ports("fixture", ["127.0.0.1"], ["tcp", "udp"])
    assert store.coverage("fixture")["total_ports"] == 131070
    assert store.ports("fixture", 131069, 1)[0]["port"] == 65535
    records = parse_batch(xml(), "127.0.0.1", "tcp", [1, 2, 3], "7.95")
    store.ports_batch("fixture", records)
    store.interrupt("fixture", "cancelled")
    coverage = store.coverage("fixture")
    assert coverage["completed_ports"] == 3 and coverage["statuses"]["cancelled"] == 131067
    assert store.ports("fixture", 3, 1)[0]["assessment_status"] == "cancelled"
    assert len(store.events("fixture")) == 3


def test_nmap_scope_aggregation_and_confidence():
    explicit = '<port portid="2" protocol="tcp"><state state="open"/><service name="http" method="probed" conf="10" product="Fixture" version="1"/></port>'
    records = parse_batch(xml(explicit=explicit, extras='<extraports state="filtered" count="2"/>'), "127.0.0.1", "tcp", [1, 2, 3], "7.95")
    assert [item["state"] for item in records] == ["filtered", "open", "filtered"]
    assert records[1]["fingerprint_confidence"] == 1
    assert records[0]["service"] == "unknown"
    ambiguous = parse_batch(xml(extras='<extraports state="closed" count="1"/><extraports state="filtered" count="2"/>'),
                            "127.0.0.1", "tcp", [1, 2, 3], "7.95")
    assert all(item["assessment_status"] == "incomplete" for item in ambiguous)
    mixed = parse_batch(xml(extras='<extraports state="closed" count="1"><extrareasons ports="1"/></extraports>'
                        '<extraports state="filtered" count="2"><extrareasons ports="2-3"/></extraports>'),
                        "127.0.0.1", "tcp", [1, 2, 3], "7.95")
    assert [item["state"] for item in mixed] == ["closed", "filtered", "filtered"]
    udp = parse_batch(xml(protocol="udp", extras='<extraports state="open|filtered" count="3"/>'),
                      "127.0.0.1", "udp", [1, 2, 3], "7.95")
    assert all(item["state"] == "open|filtered" for item in udp)


@pytest.mark.parametrize("changes", [{"host": "192.0.2.1"}, {"version": "unapproved"}, {"finished": "error"},
                                     {"explicit": '<port protocol="tcp" portid="4"><state state="open"/></port>'}])
def test_nmap_rejects_untrusted_or_out_of_scope_results(changes):
    with pytest.raises(ValueError):
        parse_batch(xml(**changes), "127.0.0.1", "tcp", [1, 2, 3], "7.95")


def test_port_range_validation():
    assert port_set("1-65535") == set(range(1, 65536))
    for bad in ("0", "65536", "3-1", "1-2-3"):
        with pytest.raises(ValueError):
            port_set(bad)


def test_nmap_command_is_bounded_and_scoped(settings, monkeypatch):
    from cyrblu_recon.tools import nmap
    executable = Path(__file__)
    monkeypatch.setattr(nmap.shutil, "which", lambda _: str(executable))
    seen = []

    async def command(arguments, directory, timeout):
        seen.append(arguments)
        if "--version" in arguments:
            return 0, b"Nmap version 7.95", b""
        return 0, xml(), b""

    monkeypatch.setattr(nmap, "command", command)
    records, evidence = asyncio.run(NmapWorker(settings).batch("127.0.0.1", "tcp", [1, 2, 3], True))
    assert len(records) == 3 and evidence["xml_sha256"]
    assert seen[-1][-1] == "127.0.0.1"
    assert "-sT" in seen[-1] and "-sV" in seen[-1] and "--version-light" in seen[-1]
    assert "--script" not in seen[-1] and "-A" not in seen[-1]


def test_invalid_batch_rejected_before_any_execution(settings):
    with pytest.raises(ValueError, match="contiguous"):
        asyncio.run(NmapWorker(settings).batch("127.0.0.1", "tcp", [1, 3], False))


def test_nonstandard_tls_and_nonmodel_json(settings, monkeypatch):
    from cyrblu_recon.tools import http
    import httpx
    actual = httpx.AsyncClient
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"unrelated": True})

    def client(**options):
        assert options["verify"] is True and options["trust_env"] is False and options["follow_redirects"] is False
        return actual(transport=httpx.MockTransport(handler), **options)

    monkeypatch.setattr(http.httpx, "AsyncClient", client)

    async def test():
        worker = HTTPWorker(settings)
        for path in ("/v1/models", "/api/tags", "/openapi.json"):
            observation = await worker.observe("127.0.0.1", 4444, path, tls=True)
            assert "models" not in observation and "api_paths" not in observation
    asyncio.run(test())
    assert all(request.url.scheme == "https" and request.url.port == 4444 for request in requests)


def test_dns_rejects_scope_expansion(settings, monkeypatch):
    async def test():
        loop = asyncio.get_running_loop()

        async def forbidden(*args, **kwargs):
            return [(2, 1, 6, "", ("192.0.2.1", 0))]

        monkeypatch.setattr(loop, "getaddrinfo", forbidden)
        with pytest.raises(ValueError, match="outside"):
            await resolve(["lab.invalid"], settings)
    asyncio.run(test())


def test_real_loopback_http_ai_observation(settings, store, http_fixture):
    async def test():
        worker = HTTPWorker(settings)
        for path in ("/", "/openapi.json", "/v1/models", "/api/tags", "/.well-known/agent-card.json", "/mcp"):
            observation = await worker.observe("127.0.0.1", http_fixture, path)
            assert "set-cookie" not in observation["headers"] and not observation["raw_body_retained"]
            ref = store.capture("fixture", "http", "ACTIVE", observation)
            http_intelligence("fixture", observation, ref, store)
    asyncio.run(test())
    assets = store.assets("fixture")
    assert {"api", "model", "model_server", "a2a_service"} <= {item["kind"] for item in assets}
    assert not any(item["kind"] == "mcp_server" for item in assets)
    assert all(item["inferred"] for item in assets if item["kind"] == "model")


def test_signed_terminal_publication_and_tamper(settings, store):
    store.save(record())
    document = publish(payload(store, "fixture"), settings.config_dir / "signing.pem").model_dump()
    assert verify(document, settings.config_dir / "signing.pub").payload.assessment_id == "fixture"
    changed = copy.deepcopy(document)
    changed["payload"]["limitations"].append("tampered")
    with pytest.raises(InvalidSignature):
        verify(changed, settings.config_dir / "signing.pub")
    changed = copy.deepcopy(document)
    changed["payload"]["schema_version"] = "2.0"
    with pytest.raises(ValueError):
        verify(changed, settings.config_dir / "signing.pub")
    store.save(record(status="running"))
    with pytest.raises(ValueError):
        payload(store, "fixture")


def test_evidence_corruption_blocks_publication(settings, store):
    store.save(record())
    identifier = store.capture("fixture", "fixture", "PASSIVE", {"value": "original"})
    with store.connection() as db:
        db.execute("UPDATE evidence SET document=json_set(document,'$.observation.value','tampered') WHERE id=?", (identifier,))
    with pytest.raises(ValueError, match="integrity"):
        payload(store, "fixture")


def test_supplied_architecture_golden_inventory(settings, store):
    entries = json.loads((Path(__file__).parent / "lab/inventory.json").read_text())

    async def test():
        engine = Engine(settings, store)
        assessment = Assessment(title="Supplied architecture golden fixture", mode="AUTHENTICATED",
                                authorization_reference="synthetic export", approved=True, inventory=entries)
        document = engine.create(assessment)
        await engine.tasks[document["id"]]
        assert store.assessment(document["id"])["status"] == "completed"
        assets = store.assets(document["id"])
        expected = {(item["kind"], item["name"]) for item in entries}
        discovered = {(item["kind"], item["name"]) for item in assets}
        assert discovered == expected
        assert all(item["inferred"] and item["confidence"] == 0.7 for item in assets)
        assert store.coverage(document["id"])["total_ports"] == 0
    asyncio.run(test())


def test_independent_api_lifecycle_roles_report_and_stream(settings):
    app = create_app(settings)
    operator = {"Authorization": "Bearer " + (settings.config_dir / "operator.token").read_text()}
    viewer = {"Authorization": "Bearer " + (settings.config_dir / "viewer.token").read_text()}
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/v1/recon/assessments").status_code == 401
        assert client.post("/api/v1/recon/assessments", headers=viewer, json=spec().model_dump()).status_code == 403
        assert client.post("/api/v1/recon/assessments", headers=operator, json={**spec().model_dump(), "extra": 1}).status_code == 422
        response = client.post("/api/v1/recon/assessments", headers=operator, json=spec().model_dump())
        assert response.status_code == 202
        identifier = response.json()["id"]
        base = f"/api/v1/recon/assessments/{identifier}"
        for _ in range(100):
            assessment = client.get(base, headers=viewer).json()
            if assessment["status"] not in {"queued", "running"}:
                break
            time.sleep(0.01)
        assert assessment["status"] == "completed"
        assert len(assessment["agent_states"]) == 23
        for endpoint in ("events", "assets", "ports", "graph", "evidence", "report", "intelligence", "ports/export", "events/stream"):
            assert client.get(base + "/" + endpoint, headers=viewer).status_code == 200
        assert "not a security pass" in client.get(base + "/report", headers=viewer).text
        document = client.get(base + "/intelligence", headers=viewer).json()
        verify(document, settings.config_dir / "signing.pub")
        assert client.get(base + "/ports?limit=1001", headers=viewer).status_code == 422
        assert client.get(base + "/events?after=-1", headers=viewer).status_code == 422
        assert client.get("/api/v1/recon/assessments/missing", headers=viewer).status_code == 404
        assert client.post(base + "/cancel", headers={**operator, "Origin": "https://evil.invalid"}).status_code == 403
        assert client.post("/api/v1/recon/assessments", content=b"x" * (1024 * 1024 + 1), headers=operator).status_code == 413


def test_cancellation_retains_partial_full_range(settings, store):
    async def test():
        engine = Engine(settings, store)
        started = asyncio.Event()

        async def delayed(*args):
            started.set()
            await asyncio.Event().wait()

        engine.nmap.batch = delayed
        document = engine.create(spec(mode="ACTIVE", targets=["127.0.0.1"]))
        await started.wait()
        result = await engine.cancel(document["id"])
        assert result["status"] == "cancelled"
        assert store.coverage(document["id"])["statuses"]["cancelled"] == 65535
    asyncio.run(test())


def test_full_engine_fixture_benchmark(settings, store, tmp_path):
    async def test():
        engine = Engine(settings, store)
        batch_count = 0

        async def batch(target, protocol, ports, fingerprint):
            nonlocal batch_count
            batch_count += 1
            selected = {8001, 65535} & set(ports)
            explicit = "".join(f'<port protocol="tcp" portid="{port}"><state state="open"/>'
                               + ('<service name="ssh" method="probed" conf="10" product="FixtureSSH" version="1"/>' if port == 8001 else "")
                               + "</port>" for port in sorted(selected))
            document = xml(ports[0], ports[-1], explicit=explicit,
                           extras=f'<extraports state="closed" count="{len(ports) - len(selected)}"/>')
            return parse_batch(document, target, protocol, ports, settings.nmap_version), {
                "target": target, "protocol": protocol, "xml_sha256": hashlib.sha256(document).hexdigest(),
            }

        engine.nmap.batch = batch
        document = engine.create(spec(mode="ACTIVE", targets=["127.0.0.1"]))
        await engine.tasks[document["id"]]
        identifier = document["id"]
        assert store.assessment(identifier)["status"] == "completed"
        coverage = store.coverage(identifier)
        assert coverage["completed_ports"] == 65535 and batch_count == 256
        assert store.ports(identifier, 65534, 1)[0]["port"] == 65535
        package = publish(payload(store, identifier), settings.config_dir / "signing.pem")
        evidence_ids = {item["id"] for item in store.evidence(identifier)}
        digest = hashlib.sha256()
        verified_count = 0
        for line in port_lines(store, identifier):
            digest.update(line)
            item = json.loads(line)
            assert item["evidence_refs"] and set(item["evidence_refs"]) <= evidence_ids
            verified_count += 1
        assert verified_count == 65535 and package.payload.ports["sha256"] == digest.hexdigest()
        discovered = {item["port"] for item in store.ports(identifier, state="open")}
        assert discovered == {8001, 65535}
        metrics = {"basis": "synthetic_nmap_adapter_not_native_execution", "execution_completeness": 1.0,
                   "port_record_recall": 1.0, "evidence_reference_quality": 1.0,
                   "known_open_port_precision": 1.0, "known_open_port_recall": 1.0,
                   "native_tcp_certified": False, "native_udp_certified": False}
        (tmp_path / "golden-metrics.json").write_text(json.dumps(metrics))
        assert "Complete port inventory" in markdown(store, identifier)
    asyncio.run(test())


@pytest.mark.skipif(os.environ.get("RECON_RUN_NATIVE_GOLDEN") != "1", reason="Requires explicit isolated-lab native full-scan authorization")
def test_native_full_tcp_golden(settings, store):
    target = os.environ["RECON_GOLDEN_TARGET"]
    version = os.environ["RECON_NMAP_VERSION"]
    expected = {int(value) for value in os.environ["RECON_GOLDEN_TCP_PORTS"].split(",")}
    settings.allowed_cidrs = (target + "/32",)
    settings.nmap_version = version

    async def test():
        engine = Engine(settings, store)
        document = engine.create(spec(mode="ACTIVE", targets=[target], fingerprint_services=True))
        await engine.tasks[document["id"]]
        assert store.assessment(document["id"])["status"] == "completed"
        assert store.coverage(document["id"])["completed_ports"] == 65535
        observed = {item["port"] for item in store.ports(document["id"], limit=65535, state="open")}
        precision = len(observed & expected) / max(1, len(observed))
        recall = len(observed & expected) / len(expected)
        assert precision == recall == 1
    asyncio.run(test())


@pytest.mark.skipif(os.environ.get("RECON_RUN_NATIVE_UDP_GOLDEN") != "1", reason="Requires isolated privileged-lab UDP authorization")
def test_native_full_udp_golden(settings, store):
    target = os.environ["RECON_GOLDEN_TARGET"]
    expected = {int(value) for value in os.environ["RECON_GOLDEN_UDP_PORTS"].split(",")}
    settings.allowed_cidrs = (target + "/32",)
    settings.nmap_version = os.environ["RECON_NMAP_VERSION"]
    settings.enable_udp = True
    settings.batch_size = 32

    async def test():
        engine = Engine(settings, store)
        document = engine.create(spec(mode="ACTIVE", targets=[target], udp=True))
        await engine.tasks[document["id"]]
        assert store.assessment(document["id"])["status"] == "completed"
        assert store.coverage(document["id"])["completed_ports"] == 131070
        observed = {item["port"] for item in store.ports(document["id"], limit=131070, state="open") if item["protocol"] == "udp"}
        assert observed == expected
    asyncio.run(test())
