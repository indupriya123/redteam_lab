import asyncio
import json
import shutil
import sys

import pytest

from lab_redteam.core import Orchestrator, Policy, Store
from lab_redteam.scanners import NucleiAdapter, bounded_command, registry
from test_system import lab_server, spec


def test_tool_registry_separates_presence_from_execution():
    tools = registry("")
    assert len(tools) == 30
    assert len({item["id"] for item in tools}) == 30
    assert sum(item["adapter"] is not None for item in tools) == 1
    assert all(item["status"] == "reference_only_adapter_pending" for item in tools if item["id"] != "nuclei")


def test_scanner_needs_version_approval_and_shares_request_budget(tmp_path):
    engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.0/8"))
    with pytest.raises(ValueError, match="version approval"):
        engine.create(spec(mode="network", targets=["127.0.0.1"], scanners=["nuclei"]))
    with pytest.raises(ValueError, match="budget"):
        engine.policy.validate(spec(mode="network", targets=[f"127.0.0.{i}" for i in range(1, 9)],
                                    ports=[80, 8080, 8000], scanners=["nuclei"]))


def test_version_mismatch_blocks_scanning(monkeypatch):
    calls = []
    monkeypatch.setattr("lab_redteam.scanners.shutil.which", lambda name: sys.executable)

    async def command(arguments, directory, environment, timeout=20):
        calls.append(arguments)
        return 0, b"", b"Nuclei Engine Version: v3.0.0"

    monkeypatch.setattr("lab_redteam.scanners.bounded_command", command)
    with pytest.raises(ValueError, match="differs"):
        asyncio.run(NucleiAdapter("3.1.0").assess("http://127.0.0.1:8080/"))
    assert len(calls) == 1


def test_normalization_never_retains_raw_response_secrets(monkeypatch):
    calls = []
    monkeypatch.setattr("lab_redteam.scanners.shutil.which", lambda name: sys.executable)

    async def command(arguments, directory, environment, timeout=20):
        calls.append((arguments, environment))
        if "-version" in arguments:
            return 0, b"Nuclei Engine Version: v3.1.0", b""
        return 0, json.dumps({
            "template-id": "lab-missing-nosniff", "matched-at": "http://127.0.0.1:8080/",
            "response": "SECRET-CANARY", "request": "Authorization: SECRET",
        }).encode(), b""

    monkeypatch.setattr("lab_redteam.scanners.bounded_command", command)
    result = asyncio.run(NucleiAdapter("3.1.0").assess("http://127.0.0.1:8080/"))
    assert "SECRET" not in json.dumps(result)
    assert result["result_status"] == "scanner_alert"
    args, environment = calls[1]
    assert "-omit-raw" in args
    assert "-disable-redirects" in args
    assert "-no-interactsh" in args
    assert "-disable-update-check" in args
    assert "HTTP_PROXY" not in environment


def test_scanner_failure_is_a_gap_not_a_false_pass(tmp_path, monkeypatch):
    async def scenario():
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.1/32"), "3.1.0")
        run = engine.create(spec(mode="network", targets=["127.0.0.1"], scanners=["nuclei"]))

        async def failed(url):
            raise ValueError("Version rejected")

        monkeypatch.setattr(engine.nuclei, "assess", failed)
        await engine.assess_scanner(run, "http://127.0.0.1/")
        assert not run["findings"]
        assert any("no scanner pass" in gap for gap in run["gaps"])
    asyncio.run(scenario())


def test_subprocess_limits_apply_without_shell(tmp_path):
    async def scenario():
        with pytest.raises(TimeoutError):
            await bounded_command([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, {}, timeout=1)
        with pytest.raises(ValueError, match="64 KiB"):
            await bounded_command([sys.executable, "-c", "print('x' * 70000)"], tmp_path, {})
    asyncio.run(scenario())


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="Optional scanner not installed")
def test_installed_nuclei_correlates_real_loopback_evidence(tmp_path, lab_server):
    server, requests = lab_server

    async def scenario():
        process = await asyncio.create_subprocess_exec(
            shutil.which("nuclei"), "-version",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await process.communicate()
        import re
        version = re.search(rb"v(\d+\.\d+\.\d+)", out + err).group(1).decode()
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.1/32"), version)
        run = engine.create(spec(mode="network", targets=["127.0.0.1"], ports=[server.server_port], scanners=["nuclei"]))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        completed = engine.store.get(run["id"])
        assert completed["status"] == "completed"
        correlated = next(item for item in completed["findings"] if "x-content-type-options" in item["title"])
        assert correlated["source_tools"] == ["http_head", "nuclei"]
        assert len(correlated["evidence_refs"]) == 2
        assert "SECRET-DO-NOT-COLLECT" not in json.dumps(completed)
    asyncio.run(scenario())
    assert requests == ["HEAD", "HEAD"]
