import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cyrblu_recon.config.settings import Settings, initialize
from cyrblu_recon.database.store import Store


@pytest.fixture
def settings(tmp_path):
    configuration = tmp_path / "configuration"
    initialize(configuration)
    return Settings(configuration, tmp_path / "data", ("127.0.0.0/8",),
                    ("lab.invalid",), "7.95", print_ports=False)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "engine.sqlite3")


@pytest.fixture
def http_fixture():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            document = {
                "/openapi.json": {"openapi": "3.1.0", "paths": {"/embed": {}, "/rag": {}}},
                "/v1/models": {"data": [{"id": "synthetic-model-not-real-weights"}]},
                "/api/tags": {"models": [{"name": "synthetic-ollama-model"}]},
                "/.well-known/agent-card.json": {"name": "synthetic-agent", "skills": [], "protocolVersion": "0.3.0"},
                "/.well-known/agent.json": {"name": "synthetic-agent", "skills": []},
            }.get(self.path)
            body = json.dumps(document or {"fixture": True}).encode()
            self.send_response(200 if document or self.path == "/" else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "sensitive-value-not-to-be-collected")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
