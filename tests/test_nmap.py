import asyncio
import json
import sys
import xml.etree.ElementTree as ET

import pytest

from lab_redteam.core import Orchestrator, Policy, Store, assessment_summary
from lab_redteam.scanners import NmapAdapter
from test_system import lab_server, spec


def xml_fixture(targets, ports, open_pairs):
    root = ET.Element("nmaprun", scanner="nmap", version="7.95")
    ET.SubElement(root, "scaninfo", type="connect", protocol="tcp", services=",".join(map(str, ports)))
    for target in targets:
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "address", addr=target, addrtype="ipv4")
        records = ET.SubElement(host, "ports")
        for port in ports:
            item = ET.SubElement(records, "port", protocol="tcp", portid=str(port))
            ET.SubElement(item, "state", state="open" if (target, port) in open_pairs else "closed")
    ET.SubElement(ET.SubElement(root, "runstats"), "finished", exit="success")
    return ET.tostring(root)


def test_only_confirmed_open_ports_are_learned():
    data = xml_fixture(["127.0.0.1"], [80, 8001], {("127.0.0.1", 8001)})
    result = NmapAdapter.parse_output(data, ["127.0.0.1"], [80, 8001], "7.95")
    assert result["open_ports"] == [{"target": "127.0.0.1", "port": 8001, "protocol": "tcp",
                                    "state": "open", "application_protocol": "unverified"}]
    root = ET.fromstring(data)
    root.find("host/ports/port/state").set("state", "open|filtered")
    assert len(NmapAdapter.parse_output(ET.tostring(root), ["127.0.0.1"], [80, 8001], "7.95")["open_ports"]) == 1


def test_host_timeout_is_not_a_complete_closed_port_scan():
    root = ET.fromstring(xml_fixture(["127.0.0.1"], [8001], set()))
    host = root.find("host")
    host.set("timedout", "true")
    host.remove(host.find("ports"))
    result = NmapAdapter.parse_output(ET.tostring(root), ["127.0.0.1"], [8001], "7.95")
    assert result["incomplete_targets"] == ["127.0.0.1"]
    assert result["open_ports"] == []


@pytest.mark.parametrize("mutation", ["host", "port", "protocol", "version", "scan_type", "unfinished", "scope_ports"])
def test_xml_cannot_broaden_engagement_scope(mutation):
    root = ET.fromstring(xml_fixture(["127.0.0.1"], [8001], {("127.0.0.1", 8001)}))
    if mutation == "host":
        root.find("host/address").set("addr", "8.8.8.8")
    elif mutation == "port":
        root.find("host/ports/port").set("portid", "9999")
    elif mutation == "protocol":
        root.find("host/ports/port").set("protocol", "udp")
    elif mutation == "version":
        root.set("version", "7.94")
    elif mutation == "scan_type":
        root.find("scaninfo").set("type", "syn")
    elif mutation == "unfinished":
        root.find("runstats/finished").set("exit", "error")
    else:
        root.find("scaninfo").set("services", "8001,9999")
    with pytest.raises(ValueError):
        NmapAdapter.parse_output(ET.tostring(root), ["127.0.0.1"], [8001], "7.95")


def test_nmap_command_is_version_approved_and_connect_only(monkeypatch):
    calls = []
    monkeypatch.setattr("lab_redteam.scanners.shutil.which", lambda name: sys.executable)

    async def command(arguments, directory, environment, timeout=20):
        calls.append(arguments)
        if "--version" in arguments:
            return 0, b"Nmap version 7.95 ( https://nmap.org )", b""
        return 0, xml_fixture(["127.0.0.1"], [8001], {("127.0.0.1", 8001)}), b""

    monkeypatch.setattr("lab_redteam.scanners.bounded_command", command)
    result = asyncio.run(NmapAdapter("7.95").discover(["127.0.0.1"], [8001]))
    assert result["open_ports"][0]["port"] == 8001
    assert "-sT" in calls[1] and "-Pn" in calls[1] and "-n" in calls[1]
    assert calls[1][-1] == "127.0.0.1"
    assert "--script" not in calls[1] and "-sV" not in calls[1] and "-A" not in calls[1]
    with pytest.raises(ValueError, match="operator approval"):
        asyncio.run(NmapAdapter("7.94").discover(["127.0.0.1"], [8001]))


def test_discovered_port_drives_real_loopback_http_checks(tmp_path, monkeypatch, lab_server):
    server, methods = lab_server

    async def scenario():
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.1/32"), nmap_version="7.95")

        async def discovery(targets, ports):
            parsed = NmapAdapter.parse_output(xml_fixture(targets, ports, {("127.0.0.1", server.server_port)}),
                                             targets, ports, "7.95")
            return {"test": "Nmap TCP discovery", **parsed, "limitations": "Controlled adapter fixture"}

        monkeypatch.setattr(engine.nmap, "discover", discovery)
        run = engine.create(spec(mode="network", targets=["127.0.0.1"], ports=[8001, server.server_port], scanners=["nmap"]))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = engine.store.get(run["id"])
        assert result["status"] == "completed"
        assert result["discovered_services"][0]["port"] == server.server_port
        assert len(result["findings"]) == 2
        assert assessment_summary(result)["requested_endpoints"] == 1
        assert assessment_summary(result)["hardening_assessed_endpoints"] == 1
        assert result["http_requests_started"] == 1
        assert "SECRET-DO-NOT-COLLECT" not in json.dumps(result)
    asyncio.run(scenario())
    assert methods == ["HEAD"]


def test_nmap_broker_rejects_out_of_scope_followup(tmp_path, monkeypatch):
    async def scenario():
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.1/32"), nmap_version="7.95")

        async def poisoned(targets, ports):
            return {"open_ports": [{"target": "127.0.0.1", "port": 9999, "protocol": "tcp", "state": "open"}]}

        monkeypatch.setattr(engine.nmap, "discover", poisoned)
        run = engine.create(spec(mode="network", targets=["127.0.0.1"], ports=[8001], scanners=["nmap"]))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = engine.store.get(run["id"])
        assert result["status"] == "failed"
        assert not result["evidence"]
        assert not result["findings"]
    asyncio.run(scenario())


def test_nmap_followup_budget_is_shared_across_hosts(tmp_path, monkeypatch):
    async def scenario():
        targets = ["127.0.0.1", "127.0.0.2"]
        ports = list(range(8000, 8020))
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.0/8"), nmap_version="7.95")
        visits = []

        async def discovery(targets, ports):
            parsed = NmapAdapter.parse_output(
                xml_fixture(targets, ports, {(target, port) for target in targets for port in ports}),
                targets, ports, "7.95",
            )
            return {"test": "Nmap TCP discovery", **parsed, "limitations": "Fixture"}

        async def headers(client, method, url):
            visits.append(url)
            return 200, {"content-type": "text/html"}

        monkeypatch.setattr(engine.nmap, "discover", discovery)
        monkeypatch.setattr(engine, "request_headers", headers)
        run = engine.create(spec(mode="network", targets=targets, ports=ports, scanners=["nmap"]))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = engine.store.get(run["id"])
        assert result["status"] == "completed"
        assert result["http_requests_started"] == 32
        assert len(visits) == 32
        assert sum("127.0.0.1" in url for url in visits) == 16
        assert sum("127.0.0.2" in url for url in visits) == 16
        assert sum("budget was exhausted" in gap for gap in result["gaps"]) == 8
    asyncio.run(scenario())
