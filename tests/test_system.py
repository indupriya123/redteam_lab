import asyncio
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from lab_redteam.app import ROOT, create_app
from lab_redteam.catalogue import load_catalogue
from lab_redteam.core import Engagement, Orchestrator, Policy, Store, markdown_report
from lab_redteam.__main__ import main


def spec(**changes):
    values = {
        "title": "Test engagement",
        "objective": "Validate lab controls",
        "authorization_reference": "Synthetic approval",
        "isolated_and_authorized": True,
    }
    return Engagement(**(values | changes))


@pytest.mark.parametrize("target", [
    "8.8.8.8", "169.254.169.254", "0.0.0.0", "224.0.0.1",
    "http://127.0.0.1", "localhost", "::ffff:127.0.0.1", "fe80::1%lo0",
])
def test_target_boundaries(target):
    with pytest.raises(ValueError):
        Policy("127.0.0.0/8,192.168.56.0/24").target(target)


def test_no_scope_no_network_and_no_inferred_authorization():
    with pytest.raises(ValueError, match="disabled"):
        Policy("").validate(spec(mode="network", targets=["127.0.0.1"]))
    with pytest.raises(ValueError, match="authorization"):
        Policy("").validate(spec(isolated_and_authorized=False))
    with pytest.raises(ValueError, match="Public|Allowlist"):
        Policy("0.0.0.0/0")
    with pytest.raises(ValueError, match="not expanded"):
        Policy("192.168.56.0/24").validate(spec(mode="network", targets=["192.168.56.0/24"]))
    with pytest.raises(ValueError, match="Duplicate"):
        Policy("127.0.0.0/8").validate(spec(mode="network", targets=["127.0.0.1", "127.0.0.1"]))
    with pytest.raises(ValidationError):
        spec(ports=[True])
    with pytest.raises(ValidationError):
        spec(execute_command="not a supported field")


def test_catalogue_keeps_provenance_and_resolves_source_id_collision():
    catalogue = load_catalogue(ROOT / "references" / "AI-Agent")
    records = catalogue["techniques"]
    assert len(records) == 111
    assert len({record["id"] for record in records}) == 111
    assert all(record["execution_status"] == "reference_only" for record in records)
    assert records[-1]["source_id"] == "ENT-1"
    assert records[-1]["source_line"] == 30
    assert len(catalogue["skills"]) == 12
    assert len(catalogue["capabilities"]) == 25


def test_demo_reports_actual_fixture_results_and_retains_history(tmp_path):
    async def scenario():
        store = Store(tmp_path / "runs.db")
        engine = Orchestrator(store, Policy(""))
        first = engine.create(spec())
        second = engine.create(spec(title="Separate scope"))
        engine.start(first["id"])
        await engine.tasks[first["id"]]
        run = store.get(first["id"])
        assert run["status"] == "completed"
        assert len(run["findings"]) == 3
        assert all(finding["status"] == "simulated" for finding in run["findings"])
        assert run["evidence"][0]["fixed_result"] == ["PUBLIC-DEMO"]
        assert run["evidence"][1]["executed"] is False
        assert run["evidence"][2]["fixed_publish_allowed"] is False
        assert store.get(second["id"])["evidence"] == []
        text = markdown_report(run)
        assert "No target compromise" in text
        assert "Recommendations" in text or "Recommendation:" in text
        assert "Retest:" in text
        assert "Gaps and untested areas" in text
        reloaded = Store(tmp_path / "runs.db").get(first["id"])
        assert reloaded["events"] == run["events"]
        with pytest.raises(ValueError, match="pending"):
            engine.start(first["id"])
    asyncio.run(scenario())


@pytest.fixture
def lab_server():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append(self.command)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "SECRET-DO-NOT-COLLECT")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_real_loopback_check_only_heads_and_does_not_collect_secrets(tmp_path, lab_server):
    server, requests = lab_server

    async def scenario():
        store = Store(tmp_path / "runs.db")
        engine = Orchestrator(store, Policy("127.0.0.1/32"))
        run = engine.create(spec(mode="network", targets=["127.0.0.1"], ports=[server.server_port]))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        run = store.get(run["id"])
        assert run["status"] == "completed"
        assert len(run["findings"]) == 2
        assert all(item["severity"] == "LOW" for item in run["findings"])
        assert "SECRET-DO-NOT-COLLECT" not in json.dumps(run)
        assert run["evidence"][0]["body_collected"] is False
        assert any("not assessed" in gap for gap in run["gaps"])
    asyncio.run(scenario())
    assert requests == ["HEAD"]


def test_redirect_is_not_followed_and_is_not_reported_as_pass(tmp_path, monkeypatch):
    real_client = httpx.AsyncClient
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    monkeypatch.setattr("lab_redteam.core.httpx.AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))

    async def scenario():
        store = Store(tmp_path / "runs.db")
        engine = Orchestrator(store, Policy("127.0.0.1/32"))
        run = engine.create(spec(mode="network", targets=["127.0.0.1"], ports=[80]))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        completed = store.get(run["id"])
        assert not completed["findings"]
        assert any("302" in gap for gap in completed["gaps"])
    asyncio.run(scenario())
    assert seen == ["http://127.0.0.1/"]


def test_queue_is_bounded_isolated_and_cancelled_before_worker_start(tmp_path):
    async def scenario():
        store = Store(tmp_path / "runs.db")
        engine = Orchestrator(store, Policy("127.0.0.1/32"))
        gate = asyncio.Event()

        async def blocked(run, engagement):
            await gate.wait()

        engine.discover = blocked
        runs = [engine.create(spec(mode="network", targets=["127.0.0.1"], title=str(i))) for i in range(3)]
        for run in runs:
            engine.start(run["id"])
        await asyncio.sleep(0.01)
        assert [store.get(run["id"])["status"] for run in runs] == ["running", "running", "queued"]
        stopped = await engine.stop(runs[2]["id"])
        assert stopped["status"] == "cancelled"
        gate.set()
        await asyncio.gather(*engine.tasks.values())
        assert all(not store.get(run["id"])["findings"] for run in runs)
        immediate = engine.create(spec())
        engine.start(immediate["id"])
        assert (await engine.stop(immediate["id"]))["status"] == "cancelled"
    asyncio.run(scenario())


def test_restart_marks_pending_execution_interrupted(tmp_path):
    store = Store(tmp_path / "runs.db")
    engine = Orchestrator(store, Policy(""))
    run = engine.create(spec())
    run["status"] = "queued"
    store.save(run)
    store.recover()
    assert store.get(run["id"])["status"] == "interrupted"


def test_model_is_advisory_and_failures_are_explicit(tmp_path, monkeypatch):
    real_client = httpx.AsyncClient
    sent = []

    def handler(request):
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"model_info": {"general.parameter_count": 1000}})
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"message": {"content": "Review remediation; no compromise established."}})

    monkeypatch.setattr("lab_redteam.core.httpx.AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))

    async def scenario():
        store = Store(tmp_path / "runs.db")
        engine = Orchestrator(store, Policy(""))
        run = engine.create(spec(model="local-test"))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = store.get(run["id"])
        assert result["model_review"]["status"] == "advisory_unverified"
        assert len(result["findings"]) == 3
        assert "tools" not in sent[0]
        assert sent[0]["stream"] is False

        def failed(request):
            return httpx.Response(404, json={"error": "model not installed"})

        monkeypatch.setattr("lab_redteam.core.httpx.AsyncClient",
                            lambda **kwargs: real_client(transport=httpx.MockTransport(failed), **kwargs))
        run = engine.create(spec(model="missing"))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = store.get(run["id"])
        assert result["status"] == "completed"
        assert result["model_review"]["status"] == "failed"
        assert any("review failed" in gap for gap in result["gaps"])
    asyncio.run(scenario())


def test_dashboard_approval_origin_and_download_lifecycle(tmp_path):
    app = create_app(tmp_path, cidrs="")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        page = client.get("/")
        assert page.status_code == 200
        token = re.search(r'name="lab-token" content="([^"]+)"', page.text).group(1)
        assert client.post("/api/runs", json=spec().model_dump()).status_code == 403
        headers = {"x-lab-token": token}
        assert client.post("/api/runs", json=spec().model_dump(),
                           headers=headers | {"origin": "http://evil.invalid"}).status_code == 403
        response = client.post("/api/runs", json=spec().model_dump(), headers=headers)
        assert response.status_code == 201
        run_id = response.json()["id"]
        assert client.post(f"/api/runs/{run_id}/approve", json={"approve": False}, headers=headers).status_code == 400
        assert client.post(f"/api/runs/{run_id}/approve", json={"approve": True}, headers=headers).status_code == 200
        for _ in range(20):
            run = client.get(f"/api/runs/{run_id}").json()
            if run["status"] == "completed":
                break
        assert run["status"] == "completed"
        assert client.get(f"/api/runs/{run_id}/report").status_code == 200
        assert client.get(f"/api/runs/{run_id}/report?format=json").json()["id"] == run_id
        assert client.get("/api/runs/missing").status_code == 404
        assert client.get("/", headers={"Host": "evil.invalid"}).status_code == 400


def test_remote_model_metadata_blocks_context_transmission(tmp_path, monkeypatch):
    real_client = httpx.AsyncClient
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={
            "remote_host": "https://cloud.example.invalid",
            "model_info": {"general.parameter_count": 1000},
        })

    monkeypatch.setattr("lab_redteam.core.httpx.AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))

    async def scenario():
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy(""))
        run = engine.create(spec(model="remote-alias"))
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        result = engine.store.get(run["id"])
        assert result["model_review"]["status"] == "failed"
        assert "Remote/cloud" in result["model_review"]["error"]
    asyncio.run(scenario())
    assert paths == ["/api/show"]


def test_concurrent_backend_cannot_recover_an_active_database(tmp_path):
    first = create_app(tmp_path, cidrs="")
    second = create_app(tmp_path, cidrs="")
    with TestClient(first, base_url="http://127.0.0.1"):
        with pytest.raises(RuntimeError, match="Another backend"):
            with TestClient(second, base_url="http://127.0.0.1"):
                pass


def test_rate_limit_is_shared_between_engagements(tmp_path):
    async def scenario():
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy(""))
        starts = []

        async def start_request():
            await engine.pace_request()
            starts.append(asyncio.get_running_loop().time())

        await asyncio.gather(start_request(), start_request())
        assert starts[1] - starts[0] >= 0.49
    asyncio.run(scenario())


def test_launcher_enforces_single_loopback_backend(monkeypatch):
    calls = []
    monkeypatch.setattr("lab_redteam.__main__.uvicorn.run", lambda *args, **kwargs: calls.append((args, kwargs)))
    main(["--port", "8766"])
    assert calls[0][1] == {"factory": True, "host": "127.0.0.1", "port": 8766, "workers": 1}
    with pytest.raises(SystemExit):
        main(["--port", "80"])
