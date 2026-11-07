import asyncio
import hashlib
import json

import httpx

from ..config.settings import Settings

PATHS = ("/", "/openapi.json", "/v1/models", "/api/tags", "/.well-known/agent-card.json", "/.well-known/agent.json", "/mcp")
HEADERS = {"content-type", "server", "x-powered-by", "www-authenticate", "content-security-policy",
           "x-content-type-options", "strict-transport-security"}


class HTTPWorker:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def observe(self, target: str, port: int, path: str, tls: bool | None = None) -> dict:
        self.settings.ip(target)
        if path not in PATHS:
            raise ValueError("Endpoint is outside approved discovery profile")
        host = f"[{target}]" if ":" in target else target
        scheme = "https" if (tls if tls is not None else port in {443, 8443}) else "http"
        url = f"{scheme}://{host}:{port}{path}"
        async with httpx.AsyncClient(timeout=5, verify=True, follow_redirects=False, trust_env=False) as client:
            async with asyncio.timeout(8):
                async with client.stream("GET", url, headers={"User-Agent": "CyrbluRecon/0.1 authorized-discovery"}) as response:
                    headers = {name: value[:500] for name, value in response.headers.items() if name in HEADERS}
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 65536:
                            raise ValueError("Discovery response exceeds 64 KiB; content not retained")
                    observation = {"url": url, "target": target, "port": port, "path": path,
                                   "status": response.status_code, "headers": headers,
                                   "body_sha256": hashlib.sha256(body).hexdigest(), "raw_body_retained": False}
                    if "json" in headers.get("content-type", "") and 200 <= response.status_code < 300:
                        try:
                            document = json.loads(body)
                        except ValueError as exc:
                            raise ValueError("Discovery endpoint advertised JSON but returned invalid JSON") from exc
                        if isinstance(document, dict):
                            observation["json_keys"] = list(document)[:50]
                            if path == "/v1/models" and "data" in document:
                                if not isinstance(document.get("data", []), list):
                                    raise ValueError("Invalid model-list schema")
                                observation["models"] = [
                                    str(item["id"])[:200] for item in document.get("data", [])[:100]
                                    if isinstance(item, dict) and isinstance(item.get("id"), str)
                                ]
                            elif path == "/api/tags" and "models" in document:
                                if not isinstance(document.get("models", []), list):
                                    raise ValueError("Invalid Ollama model-list schema")
                                observation["models"] = [
                                    str(item["name"])[:200] for item in document.get("models", [])[:100]
                                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                                ]
                            elif path == "/openapi.json" and "paths" in document and (
                                isinstance(document.get("openapi"), str) or document.get("swagger") == "2.0"
                            ):
                                if not isinstance(document.get("paths", {}), dict):
                                    raise ValueError("Invalid OpenAPI paths schema")
                                observation["api_paths"] = [str(value)[:200] for value in list(document.get("paths", {}))[:200]]
                            elif path in {"/.well-known/agent-card.json", "/.well-known/agent.json"}:
                                observation["agent_name"] = str(document.get("name", "unknown"))[:200]
                    return observation
