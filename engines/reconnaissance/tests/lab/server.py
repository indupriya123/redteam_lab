import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        fixtures = {
            "/": {"name": "Cyrblu isolated golden fixture"},
            "/openapi.json": {"openapi": "3.1.0", "paths": {"/rag": {}, "/embed": {}}},
            "/v1/models": {"data": [{"id": "synthetic-model"}]},
            "/api/tags": {"models": [{"name": "synthetic-model"}]},
            "/.well-known/agent-card.json": {"name": "synthetic-agent", "skills": [], "protocolVersion": "0.3.0"},
        }
        body = json.dumps(fixtures.get(self.path, {"error": "not found"})).encode()
        self.send_response(200 if self.path in fixtures else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", 9001))
        while True:
            _, source = server.recvfrom(2048)
            server.sendto(b"CYRBLU_SYNTHETIC_UDP_FIXTURE", source)


threading.Thread(target=udp, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
