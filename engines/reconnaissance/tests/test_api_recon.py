import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from cyrblu_recon.app import create_app
from cyrblu_recon.intelligence.signing import verify
from cyrblu_recon.orchestrator.engine import Engine
from cyrblu_recon.reporting.report import payload
from cyrblu_recon.schemas.models import Assessment, SuppliedDocument
from cyrblu_recon.tools.api_recon import APIRecon
from cyrblu_recon.tools.exports import ingest_exports
from cyrblu_recon.tools.openapi import document, parse
from cyrblu_recon.tools.scope import URLScope

SOURCE = "http://127.0.0.1:8001/openapi.json"


def specification(version="3.1.0"):
    return {"openapi": version, "info": {"title": "Synthetic golden API", "version": "1"},
            "security": [{"Bearer": []}], "components": {
                "securitySchemes": {"Bearer": {"type": "http", "scheme": "bearer"}},
                "schemas": {"Node": {"type": "object", "properties": {
                    "child": {"$ref": "#/components/schemas/Node"}, "password": {"type": "string", "example": "do-not-retain"}}}}},
            "paths": {"/users/{id}": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                                                       {"name": "q", "in": "query", "schema": {"type": "string"}}],
                        "get": {"operationId": "getUser", "security": [], "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "integer"}}],
                            "responses": {"200": {"description": "OK"}}},
                        "post": {"deprecated": True, "requestBody": {"content": {"application/json": {
                            "schema": {"$ref": "#/components/schemas/Node"}}}}, "responses": {"201": {"description": "Created"}}}}}}


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_all_methods_security_parameters_and_recursive_schemas(version):
    result = parse(SOURCE, {SOURCE: specification(version)})
    assert len(result["operations"]) == 2 and result["analysis_complete"]
    get, post = result["operations"]
    assert get["method"] == "GET" and post["method"] == "POST"
    assert get["authentication"] == "not_declared_or_optional" and post["authentication"] == "declared_required"
    assert next(item for item in get["parameters"] if item["name"] == "q")["schema"]["type"] == "integer"
    assert post["deprecated"] and "circular" in json.dumps(post["request_body"])
    assert "do-not-retain" not in json.dumps(result)
    assert all(item["validation_status"] == "unverified" for item in result["operations"])


def test_swagger_yaml_and_external_path_references():
    value = document('swagger: "2.0"\nhost: 127.0.0.1:8001\nbasePath: /v2\nschemes: [http]\npaths:\n  /items:\n    get:\n      produces: [application/json]\n      responses:\n        "200": {description: OK}\n')
    result = parse(SOURCE, {SOURCE: value})
    assert result["operations"][0]["servers"] == ["http://127.0.0.1:8001/v2"]
    assert result["operations"][0]["produces"] == ["application/json"]
    value = specification()
    value["paths"] = {"/external": {"$ref": "common.json#/path"}}
    common = "http://127.0.0.1:8001/common.json"
    result = parse(SOURCE, {SOURCE: value, common: {"path": {"get": {"responses": {"200": {"description": "OK"}}},
                                                          "head": {"responses": {"200": {"description": "OK"}}}}}})
    assert {op["method"] for op in result["operations"]} == {"GET", "HEAD"}
    assert result["analysis_complete"]


def test_unresolved_refs_and_malformed_operations_are_not_complete():
    value = specification()
    value["paths"]["/broken"] = {"delete": "invalid", "get": {"requestBody": {"$ref": "#/missing"}}}
    result = parse(SOURCE, {SOURCE: value})
    assert len(result["operations"]) == 4 and not result["analysis_complete"]
    assert result["failed_references"] and result["errors"]
    for invalid in ('value: &anchor [x]\nother: *anchor', '!!python/object/apply:os.system ["not-executed"]', "[1,2]"):
        with pytest.raises(ValueError):
            document(invalid)


def test_schema_reference_expansion_budget_remains_incomplete():
    value = specification()
    value["components"]["schemas"] = {"Large": {"type": "string", "description": "x" * 200000}}
    value["paths"] = {"/large": {"get": {"requestBody": {"content": {"application/json": {
        "schema": {"allOf": [{"$ref": "#/components/schemas/Large"}] * 30}}}}}}}
    result = parse(SOURCE, {SOURCE: value})
    assert not result["analysis_complete"]
    assert len(result["operations"]) == 1 and result["operations"][0]["analysis_error"]


def test_origin_exclusion_dns_pinning_and_secret_urls(settings, monkeypatch):
    scope = URLScope(settings, ["https://lab.invalid/"], ["https://lab.invalid/private"])
    for url in ("https://lab.invalid/pri%76ate/data", "https://third-party.invalid/openapi.json",
                "https://lab.invalid/openapi.json?token=do-not-retain"):
        with pytest.raises(ValueError):
            scope.check(url)

    async def test():
        loop = asyncio.get_running_loop()

        async def allowed(*args, **kwargs):
            return [(2, 1, 6, "", ("127.0.0.1", 443))]

        monkeypatch.setattr(loop, "getaddrinfo", allowed)
        pinned, host, sni = await scope.pin("https://lab.invalid/openapi.json")
        assert pinned == "https://127.0.0.1:443/openapi.json"
        assert host == "lab.invalid:443" and sni == "lab.invalid"

        async def forbidden(*args, **kwargs):
            return [(2, 1, 6, "", ("192.0.2.1", 443))]

        monkeypatch.setattr(loop, "getaddrinfo", forbidden)
        with pytest.raises(ValueError, match="outside"):
            await scope.pin("https://lab.invalid/openapi.json")
    asyncio.run(test())


def test_recursive_discovery_documented_routes_and_safe_get_only(settings, store):
    observed = []
    value = {"openapi": "3.1.0", "info": {"title": "Fixture", "version": "1"},
             "servers": [{"url": "/"}], "paths": {
                 "/public": {"get": {"responses": {"200": {"description": "OK"}}}, "post": {"responses": {"201": {"description": "Created"}}}},
                 "/protected": {"get": {"security": [{"Bearer": []}], "responses": {"401": {"description": "Protected"}}}},
                 "/external": {"$ref": "../common.json#/path"}}}

    def handler(request):
        observed.append(request)
        path = request.url.path
        if path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text='<a href="/custom/schema.yaml">API schema</a><script src="/app.js"></script>')
        if path == "/custom/schema.yaml":
            return httpx.Response(200, json=value)
        if path == "/common.json":
            return httpx.Response(200, json={"path": {"get": {"responses": {"200": {"description": "OK"}}}}})
        if path == "/app.js":
            return httpx.Response(200, headers={"content-type": "application/javascript"}, text="fetch('/undocumented');")
        if path == "/public":
            return httpx.Response(200, json={"result": "metadata"})
        if path == "/protected":
            return httpx.Response(401)
        return httpx.Response(404)

    async def test():
        recon = APIRecon(settings, store, "fixture", "ACTIVE", ["http://127.0.0.1:8001/"],
                         safe_get_paths=["/public", "/protected"], transport=httpx.MockTransport(handler))
        recon.delay = 0
        await recon.discover()
        await recon.probe_approved_operations()
        summary = recon.summary()
        assert summary["total_operations"] == 4 and summary["analysis_complete"]
        assert summary["authentication_protected_operations"] == 1
        assert summary["unverified_operations"] == 2 and not summary["execution_coverage_complete"]
        comparisons = store.records("fixture", "api_route_comparison")
        assert any(row["url"].endswith("/undocumented") and row["classification"] == "undocumented_candidate" for row in comparisons)
        assert any(row["response_status"] == 404 and row["classification"] == "inaccessible" for row in comparisons)
    asyncio.run(test())
    assert all(request.method == "GET" for request in observed)
    assert not any(request.url.path == "/undocumented" for request in observed)
    assert store.executions("fixture") and all(item["status"] == "completed" for item in store.executions("fixture"))


def test_out_of_scope_refs_and_limits_preserve_incomplete_coverage(settings, store):
    value = specification()
    value["paths"]["/outside"] = {"$ref": "http://192.0.2.1/definition.json#/path"}
    observed = []

    def handler(request):
        observed.append(str(request.url))
        return httpx.Response(200, json=value) if request.url.path == "/openapi.json" else httpx.Response(404)

    async def test():
        recon = APIRecon(settings, store, "fixture", "ACTIVE", [SOURCE], transport=httpx.MockTransport(handler))
        recon.delay = 0
        await recon.discover()
        assert not recon.summary()["analysis_complete"]
        assert recon.summary()["failed_references"]
    asyncio.run(test())
    assert not any("192.0.2.1" in url for url in observed)


def test_offline_api_assessment_persistence_report_and_signature(settings):
    app = create_app(settings)
    headers = {"Authorization": "Bearer " + (settings.config_dir / "operator.token").read_text()}
    with TestClient(app) as client:
        response = client.post("/api/v1/recon/assessments", headers=headers, json={
            "title": "Offline operation analysis", "mode": "PASSIVE", "domains": ["api"],
            "approved": True, "authorization_reference": "synthetic controlled documents",
            "documents": [{"format": "openapi", "name": "schema.json", "source_reference": "customer fixture",
                           "content": specification()}]})
        assert response.status_code == 202, response.text
        identifier = response.json()["id"]
        for _ in range(100):
            data = client.get(f"/api/v1/recon/assessments/{identifier}", headers=headers).json()
            if data["status"] not in {"queued", "running"}:
                break
            time.sleep(.01)
        assert data["status"] == "completed" and data["api_coverage"]["total_operations"] == 2
        assert data["recommended_next_actions"] and all(not action["automatic_execution"] for action in data["recommended_next_actions"])
        assert data["spec"]["documents"][0]["content"] == "[RAW CONTENT NOT RETAINED]"
        rows = client.get(f"/api/v1/recon/assessments/{identifier}/intelligence/api_operation", headers=headers).json()
        assert len(rows["records"]) == 2
        assert "do-not-retain" not in json.dumps(rows)
        package = client.get(f"/api/v1/recon/assessments/{identifier}/intelligence", headers=headers).json()
        verify(package, settings.config_dir / "signing.pub")
        assert len([item for item in package["payload"]["applications"] if item["kind"] == "api_operation"]) == 2
        assert package["payload"]["coverage"]["api"]["unverified_operations"] == 2
        for format in ("json", "html", "markdown"):
            assert client.get(f"/api/v1/recon/assessments/{identifier}/report?format={format}", headers=headers).status_code == 200
        assert client.get(f"/api/v1/recon/assessments/{identifier}/report?format=pdf", headers=headers).status_code == 409


def test_missing_nmap_does_not_crash_authorized_api_domain(settings, store, monkeypatch):
    import cyrblu_recon.orchestrator.engine as engine_module
    actual = engine_module.APIRecon

    def factory(*args, **kwargs):
        recon = actual(*args, **kwargs, transport=httpx.MockTransport(lambda _: httpx.Response(404)))
        recon.delay = 0
        return recon

    monkeypatch.setattr(engine_module, "APIRecon", factory)

    async def test():
        engine = Engine(settings, store)

        async def unavailable(*args):
            raise ValueError("Nmap unavailable")

        engine.nmap.batch = unavailable
        spec = Assessment(title="Domain isolation", mode="ACTIVE", domains=["network", "api"], approved=True,
                          authorization_reference="synthetic", targets=["127.0.0.1"], urls=["http://127.0.0.1:8001/"])
        result = engine.create(spec)
        await engine.tasks[result["id"]]
        saved = store.assessment(result["id"])
        assert saved["status"] == "completed" and saved["domain_states"]["network"] == "failed"
        assert store.coverage(result["id"])["statuses"]["failed"] == 65535
        assert any(row["tool"] == "httpx" and row["status"] == "completed" for row in store.executions(result["id"]))
    asyncio.run(test())


def test_bloodhound_and_sbom_relationships_are_only_source_assertions(store):
    documents = [
        SuppliedDocument(format="bloodhound", name="users", source_reference="golden", content={
            "meta": {"type": "users"}, "data": [{"ObjectIdentifier": "USER-SID", "Properties": {"name": "user", "password": "not-retained"}}]}),
        SuppliedDocument(format="bloodhound", name="groups", source_reference="golden", content={
            "meta": {"type": "groups"}, "data": [{"ObjectIdentifier": "GROUP-SID", "Properties": {"name": "group"},
                                                   "Members": [{"ObjectIdentifier": "USER-SID"}],
                                                   "Aces": [{"PrincipalSID": "USER-SID", "RightName": "GenericAll"}]}]}),
        SuppliedDocument(format="cyclonedx", name="bom", source_reference="golden", content={
            "bomFormat": "CycloneDX", "components": [{"name": "langgraph", "version": "synthetic", "bom-ref": "a"},
                                                    {"name": "dependency", "version": "synthetic", "bom-ref": "b"}],
            "dependencies": [{"ref": "a", "dependsOn": ["b"]}]}),
        SuppliedDocument(format="spdx", name="spdx-bom", source_reference="golden", content={
            "spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-fixture", "name": "fixture-package",
                                                    "versionInfo": "synthetic"}]}),
    ]
    ingest_exports(store, "fixture", "AUTHENTICATED", documents)
    assert len(store.records("fixture", "ad_object")) == 2
    assert len(store.records("fixture", "supply_chain_component")) == 3
    graph = store.graph("fixture")
    assert {"member_of", "source_asserted_permission:GenericAll", "depends_on"} <= {edge["relation"] for edge in graph["inferred_edges"]}
    assert not graph["observed_edges"] and "not-retained" not in json.dumps(store.assets("fixture"))


def test_malformed_export_records_failure_without_success_inventory(store):
    ingest_exports(store, "fixture", "AUTHENTICATED", [
        SuppliedDocument(format="cyclonedx", name="invalid", source_reference="synthetic",
                         content={"bomFormat": "CycloneDX", "components": [None]})])
    assert not store.records("fixture", "supply_chain_component")
    assert store.executions("fixture")[0]["status"] == "failed"


def test_intelligence_keeps_url_scope_and_refuses_truncated_operations(store, monkeypatch):
    store.save({"id": "fixture", "status": "completed", "created_at": "synthetic",
                "spec": {"targets": [], "urls": [SOURCE], "inventory": [], "mode": "ACTIVE"}, "limitations": []})
    assert payload(store, "fixture").scope == [SOURCE]
    monkeypatch.setattr(store, "record_counts", lambda *args: {"analysed": 10001})
    with pytest.raises(ValueError, match="publication limit"):
        payload(store, "fixture")


def test_scoped_redirect_query_is_not_followed_or_retained(settings, store):
    observed = []

    def handler(request):
        observed.append(str(request.url))
        return httpx.Response(302, headers={"location": "/next?token=secret-value-never-retained"})

    async def test():
        recon = APIRecon(settings, store, "fixture", "ACTIVE", [SOURCE], transport=httpx.MockTransport(handler))
        recon.delay = 0
        recon.max_requests = 1
        await recon.discover()
        assert not recon.summary()["analysis_complete"]
    asyncio.run(test())
    assert len(observed) == 1
    assert "secret-value-never-retained" not in json.dumps(store.evidence("fixture"))


def test_existing_database_migrates_without_changing_old_assessments(tmp_path):
    import sqlite3
    from cyrblu_recon.database.store import Store
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE assessments(id TEXT PRIMARY KEY,document TEXT NOT NULL)")
        db.execute("INSERT INTO assessments VALUES ('old',?)", (json.dumps({"id": "old", "status": "completed"}),))
    store = Store(path)
    assert store.assessment("old")["status"] == "completed"
    Store(path)
    with store.connection() as db:
        assert db.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 1


def test_real_loopback_recursive_api_fixture(settings, store):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    methods = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            methods.append(("GET", self.path))
            if self.path == "/":
                body = b'<a href="/custom/openapi.json">Specification</a>'
                media, status = "text/html", 200
            elif self.path == "/custom/openapi.json":
                value = specification()
                value["paths"] = {"/metadata": {"get": {"responses": {"200": {"description": "Read-only"}}},
                                                "post": {"responses": {"201": {"description": "State-changing"}}}}}
                body = json.dumps(value).encode()
                media, status = "application/json", 200
            elif self.path == "/metadata":
                body, media, status = b'{"public_metadata":true}', "application/json", 200
            else:
                body, media, status = b"", "text/plain", 404
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Set-Cookie", "secret-cookie-never-retained")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        async def test():
            recon = APIRecon(settings, store, "fixture", "ACTIVE", [f"http://127.0.0.1:{server.server_port}/"],
                             safe_get_paths=["/metadata"])
            recon.delay = 0
            await recon.discover()
            await recon.probe_approved_operations()
            assert recon.summary()["total_operations"] == 2
            assert recon.summary()["analysis_complete"]
            assert recon.summary()["unverified_operations"] == 1
        asyncio.run(test())
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert ("GET", "/metadata") in methods
    assert "secret-cookie-never-retained" not in json.dumps(store.evidence("fixture"))
