import asyncio
import hashlib
import json
import re
from collections import Counter, deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from .http import HEADERS
from .openapi import document, parse, redact, references
from .scope import URLScope

SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/api-docs",
    "/api/docs", "/swagger-ui", "/swagger-ui.html", "/v1/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/api/v1/docs", "/api/v2/docs",
)


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in {"href", "src", "data-url"} and value:
                self.urls.add(value)


class APIRecon:
    def __init__(self, settings, store, identifier: str, mode: str, urls: list[str],
                 exclusions=(), safe_get_paths=(), transport=None):
        self.settings, self.store, self.identifier, self.mode = settings, store, identifier, mode
        self.scope = URLScope(settings, urls, exclusions)
        self.seeds = urls
        self.safe_get_paths = set(safe_get_paths)
        self.transport = transport
        self.documents: dict[str, dict] = {}
        self.sources: dict[str, str] = {}
        self.observed_routes = set()
        self.route_refs = {}
        self.route_statuses = {}
        self.requests = 0
        self.failures = []
        self.max_requests, self.max_documents, self.max_depth = 128, 32, 4
        self.delay = 0.5

    def issue(self, source: str, message: str):
        source = redact(source)
        self.failures.append({"source": source, "reason": message})
        ref = self.store.capture(self.identifier, source, self.mode, {"outcome": "incomplete", "reason": message})
        key = hashlib.sha256(f"{source}:{message}".encode()).hexdigest()
        self.store.record(self.identifier, "api_issue", key, {"reason": message}, source, [ref], "incomplete")
        self.store.event(self.identifier, "api_discovery", "Discovery limitation", {"source": source, "reason": message})

    def supply(self, source: str, content):
        parsed = document(content)
        self.documents[source] = parsed
        self.sources[source] = self.store.capture(self.identifier, source, self.mode, {
            "format": "OpenAPI/Swagger", "source_sha256": hashlib.sha256(json.dumps(parsed, sort_keys=True).encode()).hexdigest(),
            "basis": "customer_supplied_document_not_live_validation", "raw_document_retained": False,
        })

    async def request(self, url: str) -> tuple[dict, bytes]:
        if self.mode != "ACTIVE":
            raise ValueError("Only ACTIVE discovery may make requests")
        if self.requests >= self.max_requests:
            raise ValueError("Recursive discovery request budget exhausted")
        url = self.scope.check(url)
        pinned, host, sni = await self.scope.pin(url)
        self.requests += 1
        execution = self.store.execution_start(self.identifier, "api_discovery", "api_discovery", "httpx", url)
        try:
            await asyncio.sleep(self.delay)
            async with httpx.AsyncClient(timeout=5, verify=True, trust_env=False, follow_redirects=False,
                                         transport=self.transport) as client:
                async with asyncio.timeout(10):
                    async with client.stream("GET", pinned, headers={"Host": host, "User-Agent": "CyrbluRecon/0.1"},
                                             extensions={"sni_hostname": sni}) as response:
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            content.extend(chunk)
                            if len(content) > 1024 * 1024:
                                raise ValueError("Discovery body exceeds 1 MiB")
                        headers = {key: value[:500] for key, value in response.headers.items() if key in HEADERS | {"location", "link"}}
                        redirect_blocked = False
                        if "location" in headers:
                            destination = urljoin(url, headers["location"])
                            try:
                                headers["location"] = self.scope.check(destination)
                            except ValueError:
                                headers["location"] = redact(destination)
                                redirect_blocked = True
                        metadata = redact({"url": url, "status": response.status_code, "headers": headers,
                                           "body_sha256": hashlib.sha256(content).hexdigest(), "raw_body_retained": False,
                                           "redirect_blocked": redirect_blocked})
                        ref = self.store.capture(self.identifier, url, self.mode, metadata)
                        metadata["evidence_ref"] = ref
            self.store.execution_finish(execution, "completed", [ref])
            self.store.record(self.identifier, "web_route", hashlib.sha256(url.encode()).hexdigest(),
                              metadata, url, [ref], "observed")
            self.observed_routes.add(url)
            self.route_refs[url] = ref
            self.route_statuses[url] = metadata["status"]
            return metadata, bytes(content)
        except asyncio.CancelledError:
            self.store.execution_finish(execution, "cancelled", error="Operator cancelled discovery")
            raise
        except (httpx.HTTPError, TimeoutError, ValueError, OSError) as exc:
            self.store.execution_finish(execution, "failed", error=type(exc).__name__)
            raise

    async def discover(self):
        pending = deque((url, 0, "seed") for url in self.seeds)
        for seed in self.seeds:
            for path in SPEC_PATHS:
                pending.append((urljoin(seed, path), 0, "candidate"))
        seen = set()
        while pending:
            url, depth, reason = pending.popleft()
            url = urldefrag(url)[0]
            if url in seen:
                continue
            seen.add(url)
            if depth > self.max_depth:
                self.issue(url, "Recursive discovery depth exceeded")
                continue
            try:
                url = self.scope.check(url)
            except ValueError as exc:
                self.issue(url, str(exc))
                continue
            if self.requests >= self.max_requests:
                self.issue(url, f"Request budget exhausted; {len(pending) + 1} queued resources unverified")
                break
            try:
                metadata, body = await self.request(url)
            except (httpx.HTTPError, TimeoutError, ValueError, OSError) as exc:
                self.issue(url, f"Request failed: {type(exc).__name__}")
                continue
            if metadata["status"] in {301, 302, 303, 307, 308}:
                if metadata["redirect_blocked"]:
                    self.issue(url, "Redirect requires prohibited credentials, query, exclusion or third-party origin")
                    continue
                location = metadata["headers"].get("location")
                if location:
                    pending.append((urljoin(url, location), depth + 1, "redirect"))
                continue
            if not 200 <= metadata["status"] < 300:
                if reason in {"reference", "specification"}:
                    self.issue(url, f"Referenced document returned HTTP {metadata['status']}")
                continue
            media = metadata["headers"].get("content-type", "")
            is_document = "json" in media or "yaml" in media or urlsplit(url).path.endswith((".json", ".yaml", ".yml"))
            if is_document:
                try:
                    parsed = document(body)
                    if "paths" in parsed or reason == "reference":
                        if len(self.documents) >= self.max_documents:
                            raise ValueError("Document budget exhausted")
                        self.documents[url] = parsed
                        self.sources[url] = metadata["evidence_ref"]
                        for ref in references(parsed):
                            absolute = urljoin(url, ref)
                            external, _ = urldefrag(absolute)
                            if external != url:
                                pending.append((external, depth + 1, "reference"))
                        continue
                except ValueError as exc:
                    if reason in {"reference", "specification"} or urlsplit(url).path.endswith((".json", ".yaml", ".yml")):
                        self.issue(url, f"Document parsing failed: {exc}")
                    continue
            if "html" in media or "javascript" in media or reason == "seed":
                text = body.decode("utf-8", errors="replace")
                links = Links()
                links.feed(text)
                links.urls.update(re.findall(r"""["']([^"'\s]+(?:openapi|swagger|api-docs)[^"'\s]*)["']""", text, re.I))
                links.urls.update(re.findall(r"""["']([^"'\s]+\.(?:json|yaml|yml))["']""", text, re.I))
                links.urls.update(re.findall(r"""(?:fetch\s*\(|axios\.(?:get|post|put|delete)\s*\()\s*["']([^"']+)["']""", text))
                for link in sorted(links.urls)[:100]:
                    candidate = urljoin(url, link)
                    self.observed_routes.add(candidate)
                    self.route_refs[candidate] = metadata["evidence_ref"]
                    path = urlsplit(candidate).path.lower()
                    if any(marker in path for marker in ("openapi", "swagger", "api-docs")) or path.endswith((".json", ".yaml", ".yml")):
                        pending.append((candidate, depth + 1, "specification"))
                    elif path.endswith(".js") or link in self.safe_get_paths:
                        pending.append((candidate, depth + 1, "linked_metadata"))
        self.analyse()

    def analyse(self):
        documented = set()
        for source, spec in self.documents.items():
            if "openapi" not in spec and "swagger" not in spec:
                continue
            ref = self.sources[source]
            try:
                result = parse(source, self.documents)
            except (ValueError, TypeError, AttributeError) as exc:
                self.issue(source, f"Specification parsing failed: {exc}")
                self.store.record(self.identifier, "api_specification", hashlib.sha256(source.encode()).hexdigest(),
                                  {"parsing_error": str(exc), "confidence": 0}, source, [ref], "failed")
                continue
            self.store.record(self.identifier, "api_specification", hashlib.sha256(source.encode()).hexdigest(),
                              {"version": result["version"], "paths": result["paths"], "total_operations": len(result["operations"]),
                               "failed_references": result["failed_references"], "errors": result["errors"],
                               "confidence": 0.9}, source, [ref], "parsed" if result["analysis_complete"] else "incomplete")
            api = self.store.asset(self.identifier, "api", source, ref, {
                "version": result["version"], "operations": len(result["operations"]), "basis": "declared_API_schema"},
                inferred=self.mode != "ACTIVE", confidence=0.9)
            for operation in result["operations"]:
                incomplete = bool(operation.get("analysis_error") or operation.get("failed_references") or not result["analysis_complete"])
                self.store.record(self.identifier, "api_operation", operation["key"], operation, source, [ref],
                                  "incomplete" if incomplete else "analysed")
                node = self.store.asset(self.identifier, "api_operation", f"{source}::{operation['method']} {operation['path']}", ref,
                                       {"method": operation["method"], "path": operation["path"], "validation": "unverified"},
                                       inferred=True, confidence=operation["confidence"])
                self.store.edge(self.identifier, api, node, "documents", ref, False, 0.9)
                self.store.event(self.identifier, "api_discovery", "API operation analysed", {
                    "method": operation["method"], "path": operation["path"],
                    "analysis_status": "incomplete" if incomplete else "analysed",
                    "next_skill": "separately_authorized_validation",
                })
                for server in operation.get("servers", []):
                    endpoint = server.rstrip("/") + "/" + operation["path"].lstrip("/")
                    documented.add(endpoint)
            for server in result["servers"]:
                key = hashlib.sha256(server.encode()).hexdigest()
                try:
                    if self.mode == "ACTIVE":
                        self.scope.check(server)
                    status = "declared"
                except ValueError:
                    status = "out_of_scope"
                self.store.record(self.identifier, "api_server", key, {"url": server, "confidence": 0.8},
                                  source, [ref], status)
                if status == "out_of_scope":
                    self.issue(server, "Additional API server requires separate origin authorization")
        for url in self.observed_routes:
            source = redact(url)
            refs = [self.route_refs[url]] if url in self.route_refs else []
            status = self.route_statuses.get(url)
            classification = ("authentication_protected" if status in {401, 403} else
                              "inaccessible" if status is not None and not 200 <= status < 300 else
                              "documented" if url in documented else "undocumented_candidate")
            self.store.record(self.identifier, "api_route_comparison", hashlib.sha256(url.encode()).hexdigest(),
                              {"url": url, "classification": classification, "response_status": status,
                               "confidence": 0.6}, source, refs, "compared")

    async def probe_approved_operations(self):
        if self.mode != "ACTIVE":
            return
        offset = 0
        while operations := self.store.records(self.identifier, "api_operation", offset, 500):
            for operation in operations:
                if operation["method"] != "GET" or operation["path"] not in self.safe_get_paths or operation.get("kind") != "path":
                    continue
                if "{" in operation["path"]:
                    continue
                for server in operation.get("servers", []):
                    url = server.rstrip("/") + "/" + operation["path"].lstrip("/")
                    try:
                        metadata, _ = await self.request(url)
                    except (httpx.HTTPError, TimeoutError, ValueError, OSError) as exc:
                        self.issue(url, f"Approved GET validation unverified: {type(exc).__name__}")
                        continue
                    validation = "authentication_protected" if metadata["status"] in {401, 403} else (
                        "response_observed" if 200 <= metadata["status"] < 300 else "inaccessible")
                    operation["validation_status"] = validation
                    operation["response_status"] = metadata["status"]
                    self.store.record(self.identifier, "api_operation", operation["id"], operation,
                                      operation["source"], operation["evidence_refs"] + [metadata["evidence_ref"]], operation["status"])
            offset += len(operations)

    def summary(self):
        specs = self.store.record_counts(self.identifier, "api_specification")
        operations = self.store.record_counts(self.identifier, "api_operation")
        total = sum(operations.values())
        analysed = operations.get("analysed", 0)
        issues = self.store.record_counts(self.identifier, "api_issue")
        validation, authentication = Counter(), Counter()
        offset = 0
        while rows := self.store.records(self.identifier, "api_operation", offset, 500):
            validation.update(row.get("validation_status") for row in rows)
            authentication.update(row.get("authentication") for row in rows)
            offset += len(rows)
        spec_rows = self.store.records(self.identifier, "api_specification", limit=self.max_documents)
        return {"specifications_discovered": sum(specs.values()), "specifications_parsed": specs.get("parsed", 0),
                "specifications_incomplete": specs.get("incomplete", 0) + specs.get("failed", 0),
                "total_operations": total, "operations_analysed": analysed, "operations_pending": total - analysed,
                "unverified_operations": validation["unverified"],
                "authentication_protected_operations": validation["authentication_protected"],
                "requests": self.requests, "discovery_issues": sum(issues.values()),
                "documented_paths": sum(row.get("paths", 0) for row in spec_rows),
                "failed_references": sum(len(row.get("failed_references", [])) for row in spec_rows),
                "declared_authentication_operations": authentication["declared_required"],
                "operation_count_unknown": bool(specs.get("failed") or specs.get("incomplete")),
                "analysis_complete": bool(specs) and not issues and specs.get("parsed", 0) == sum(specs.values()) and analysed == total,
                "execution_coverage_complete": False}
