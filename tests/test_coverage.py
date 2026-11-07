import asyncio
import errno
import json

import httpx
import pytest

from lab_redteam.core import (
    Orchestrator, Policy, Store, assessment_summary, connection_diagnostic,
    markdown_report, run_view,
)
from test_system import spec


def install_transport(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr("lab_redteam.core.httpx.AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))


def run_network(tmp_path, engagement):
    async def scenario():
        engine = Orchestrator(Store(tmp_path / "runs.db"), Policy("127.0.0.0/8"))
        run = engine.create(engagement)
        engine.start(run["id"])
        await engine.tasks[run["id"]]
        return engine.store.get(run["id"])
    return asyncio.run(scenario())


@pytest.mark.parametrize("approved,expected_methods", [(False, ["HEAD"]), (True, ["HEAD", "GET"])])
def test_head_rejection_never_adds_unapproved_get(tmp_path, monkeypatch, approved, expected_methods):
    methods = []

    def handler(request):
        methods.append(request.method)
        if request.method == "HEAD":
            return httpx.Response(405, headers={"Allow": "GET", "Content-Type": "application/json"})
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=b"SENSITIVE-BODY-CANARY")

    install_transport(monkeypatch, handler)
    run = run_network(tmp_path, spec(mode="network", targets=["127.0.0.1"], ports=[8001], get_fallback=approved))
    assert methods == expected_methods
    assert "SENSITIVE-BODY-CANARY" not in json.dumps(run)
    assert run["evidence"][0]["headers"]["allow"] == "GET"
    summary = assessment_summary(run)
    assert summary["http_responded_endpoints"] == 1
    assert summary["hardening_assessed_endpoints"] == int(approved)
    assert summary["verdict"] == ("limited_coverage" if approved else "inconclusive")
    if approved:
        assert run["evidence"][1]["test"] == "HTTP GET"
        assert all(item["evidence_refs"] == ["E-002"] for item in run["findings"])
    else:
        assert any("not authorized" in gap for gap in run["gaps"])


@pytest.mark.parametrize("status", [200, 302, 403, 404])
def test_fallback_only_after_method_rejection(tmp_path, monkeypatch, status):
    seen = []

    def handler(request):
        seen.append(request.method)
        return httpx.Response(status, headers={"Content-Type": "text/html", "Location": "http://169.254.169.254/"})

    install_transport(monkeypatch, handler)
    run_network(tmp_path, spec(mode="network", targets=["127.0.0.1"], ports=[8001], get_fallback=True))
    assert seen == ["HEAD"]


def test_connection_diagnostic_does_not_invent_firewall_explanation():
    cause = OSError(errno.ECONNREFUSED, "Connection refused")
    error = httpx.ConnectError("Connection failed")
    error.__cause__ = cause
    assert connection_diagnostic(error)["category"] == "connection_refused"
    assert connection_diagnostic(httpx.ConnectError("unknown"))["category"] == "connection_or_protocol_error"
    assert connection_diagnostic(httpx.ReadTimeout("timeout"))["category"] == "request_timeout"


def test_pasted_report_shape_is_inconclusive_and_legacy_data_unchanged():
    run = {
        "id": "historical-run", "created_at": "2026-11-07T10:04:22+00:00", "status": "completed",
        "engagement": spec(mode="network", targets=["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"], ports=[8001]).model_dump(),
        "evidence": [{"id": "E-001", "test": "HTTP HEAD", "url": "http://127.0.0.1:8001/",
                      "status": 405, "headers": {"content-type": "application/json"}}] +
                    [{"id": f"E-00{i}", "test": "HTTP discovery", "url": f"http://127.0.0.{i}:8001/",
                      "error_type": "ConnectError"} for i in range(2, 5)],
        "events": [], "plan": [], "findings": [], "gaps": [], "model_review": None,
    }
    del run["engagement"]["get_fallback"]
    original = json.dumps(run, sort_keys=True)
    summary = run_view(run)["assessment"]
    assert summary["verdict"] == "inconclusive"
    assert summary["http_responded_endpoints"] == 1
    assert summary["hardening_assessed_endpoints"] == 0
    assert len(summary["unassessed_endpoints"]) == 4
    assert "Assessment verdict: inconclusive" in markdown_report(run)
    assert json.dumps(run, sort_keys=True) == original


def test_failed_fallback_preserves_head_evidence_and_marks_coverage_gap(tmp_path, monkeypatch):
    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(501)
        raise httpx.ConnectError("Connection failed")

    install_transport(monkeypatch, handler)
    run = run_network(tmp_path, spec(mode="network", targets=["127.0.0.1"], ports=[8001], get_fallback=True))
    assert run["evidence"][0]["status"] == 501
    assert run["evidence"][1]["method"] == "GET"
    assert run["evidence"][1]["diagnostic"]["category"] == "connection_or_protocol_error"
    assert assessment_summary(run)["verdict"] == "inconclusive"


def test_get_fallback_counts_toward_request_budget():
    with pytest.raises(ValueError, match="budget"):
        Policy("127.0.0.0/8").validate(spec(
            mode="network", targets=[f"127.0.0.{i}" for i in range(1, 9)],
            ports=[8001, 8002, 8003], get_fallback=True,
        ))
