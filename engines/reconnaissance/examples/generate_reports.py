"""Generate real loopback-fixture reports, not native infrastructure certification."""

import argparse
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from cyrblu_recon.config.settings import Settings, initialize
from cyrblu_recon.database.store import Store
from cyrblu_recon.evidence.integrity import validate
from cyrblu_recon.orchestrator.engine import Engine
from cyrblu_recon.reporting.report import html_report, structured
from cyrblu_recon.schemas.models import Assessment


def generate(output: Path):
    methods = []
    schema = {
        "openapi": "3.1.0", "info": {"title": "Synthetic loopback fixture", "version": "1"},
        "paths": {"/metadata": {
            "get": {"responses": {"200": {"description": "Public synthetic metadata"}}},
            "post": {"responses": {"201": {"description": "Documented only; never executed"}}},
        }},
    }

    class Handler(BaseHTTPRequestHandler):
        def parse_request(self):
            accepted = super().parse_request()
            if accepted:
                methods.append({"method": self.command, "path": self.path})
            return accepted

        def do_GET(self):
            if self.path == "/":
                body, media, status = b'<a href="/custom/openapi.json">Fixture schema</a>', "text/html", 200
            elif self.path == "/custom/openapi.json":
                body, media, status = json.dumps(schema).encode(), "application/json", 200
            elif self.path == "/metadata":
                body, media, status = b'{"synthetic_fixture":true}', "application/json", 200
            else:
                body, media, status = b"", "text/plain", 404
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TemporaryDirectory(prefix="cyrblu-fixture-") as temporary:
            config = Path(temporary) / "config"
            initialize(config)
            settings = Settings(config, Path(temporary), allowed_cidrs=("127.0.0.1/32",), print_ports=False)
            store = Store(Path(temporary) / "fixture.sqlite3")

            async def assess():
                engine = Engine(settings, store)
                assessment = engine.create(Assessment(
                    title="Controlled synthetic loopback fixture - not native certification",
                    mode="ACTIVE", domains=["api"], approved=True,
                    authorization_reference="Owned ephemeral loopback fixture only",
                    urls=[f"http://127.0.0.1:{server.server_port}/"], safe_get_paths=["/metadata"],
                ))
                await engine.tasks[assessment["id"]]
                return assessment["id"]

            identifier = asyncio.run(assess())
            result = structured(store, identifier)
            coverage = result["coverage"]["api"]
            if result["assessment"]["status"] != "completed" or coverage["total_operations"] != 2:
                raise RuntimeError("Fixture assessment failed; sample reports were not generated")
            expected = {("GET", "/metadata"), ("POST", "/metadata")}
            discovered = {(item["method"], item["path"]) for item in result["api_operations"]}
            correct = len(expected & discovered)
            validated_evidence = validate(result["evidence"])
            output.mkdir(parents=True, exist_ok=True)
            (output / "sample-report.json").write_text(json.dumps(result, indent=2) + "\n")
            (output / "sample-report.html").write_text(html_report(store, identifier))
            (output / "lab-results.json").write_text(json.dumps({
                "basis": "Actual HTTP requests against an owned synthetic loopback server",
                "native_infrastructure_certification": False, "native_tools_tested": [],
                "assessment_id": identifier, "api_coverage": coverage, "observed_requests": methods,
                "fixture_operation_precision": correct / len(discovered) if discovered else None,
                "fixture_operation_recall": correct / len(expected),
                "validated_evidence_records": len(validated_evidence),
                "state_changing_requests": sum(item["method"] not in {"GET", "HEAD", "OPTIONS"} for item in methods),
            }, indent=2) + "\n")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    generate(parser.parse_args().output)
