import hashlib
import json
import re
from urllib.parse import unquote, urldefrag, urljoin, urlsplit, urlunsplit

import yaml

METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
SECRET_KEYS = re.compile(r"password|secret|token|credential|authorization|api.?key|private.?key", re.I)


def redact(value, depth=0):
    if depth > 40:
        raise ValueError("Document nesting limit exceeded")
    if isinstance(value, dict):
        return {str(key): ("[REDACTED]" if key in {"example", "examples", "default"} or (
            SECRET_KEYS.search(str(key)) and not isinstance(item, (dict, list))) else redact(item, depth + 1))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, str) and re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        url = urlsplit(value)
        if url.username or url.password or url.query:
            authority = url.hostname or ""
            if url.port:
                authority += f":{url.port}"
            return urlunsplit((url.scheme, authority, url.path, "", url.fragment))
    return value


def document(value: dict | str | bytes) -> dict:
    if isinstance(value, dict):
        raw = json.dumps(value, allow_nan=False).encode()
        result = value
    else:
        raw = value.encode() if isinstance(value, str) else value
        if len(raw) > 1024 * 1024:
            raise ValueError("Specification exceeds 1 MiB")
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            try:
                if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in yaml.scan(raw)):
                    raise ValueError("YAML aliases and anchors are prohibited")
                result = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                raise ValueError("Invalid JSON/YAML specification") from exc
    if len(raw) > 1024 * 1024 or not isinstance(result, dict):
        raise ValueError("Specification must be an object within 1 MiB")
    try:
        json.dumps(result, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Specification contains non-JSON values") from exc
    redact(result)
    return result


def references(value, depth=0):
    if depth > 40:
        raise ValueError("Reference traversal depth exceeded")
    if isinstance(value, dict):
        if isinstance(value.get("$ref"), str):
            yield value["$ref"]
        for item in value.values():
            yield from references(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from references(item, depth + 1)


class Resolver:
    def __init__(self, documents: dict[str, dict]):
        self.documents = documents
        self.failed = set()
        self.nodes = 0
        self.expanded_bytes = 0

    def resolve(self, value, base: str, stack=(), depth=0):
        self.nodes += 1
        if isinstance(value, str):
            self.expanded_bytes += len(value.encode())
        elif isinstance(value, dict):
            self.expanded_bytes += sum(len(str(key).encode()) for key in value)
        else:
            self.expanded_bytes += 8
        if self.nodes > 50000 or depth > 40 or self.expanded_bytes > 4 * 1024 * 1024:
            raise ValueError("Schema resolution limit exceeded")
        if isinstance(value, list):
            return [self.resolve(item, base, stack, depth + 1) for item in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str):
                raise ValueError("Reference must be a string")
            absolute = urljoin(base, ref)
            self.expanded_bytes += len(absolute.encode())
            if self.expanded_bytes > 4 * 1024 * 1024:
                raise ValueError("Expanded reference budget exceeded")
            if absolute in stack:
                return {"$ref": absolute, "resolution": "circular"}
            source, fragment = urldefrag(absolute)
            target = self.documents.get(source)
            try:
                if target is None:
                    raise KeyError(source)
                if fragment:
                    if not fragment.startswith("/"):
                        raise KeyError(fragment)
                    for part in fragment[1:].split("/"):
                        key = unquote(part).replace("~1", "/").replace("~0", "~")
                        target = target[int(key)] if isinstance(target, list) else target[key]
            except (KeyError, IndexError, ValueError, TypeError):
                self.failed.add(absolute)
                return {"$ref": absolute, "resolution": "unresolved"}
            resolved = self.resolve(target, source, stack + (absolute,), depth + 1)
            siblings = {key: item for key, item in value.items() if key != "$ref"}
            if isinstance(resolved, dict):
                return {**resolved, **self.resolve(siblings, base, stack, depth + 1)}
            return resolved
        return {key: self.resolve(item, base, stack, depth + 1) for key, item in value.items()}


def server_urls(values: list, base: str) -> list[str]:
    result = []
    for server in values:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise ValueError("Invalid API server definition")
        value = server["url"]
        for name, variable in server.get("variables", {}).items():
            if not isinstance(variable, dict) or not isinstance(variable.get("default"), str):
                raise ValueError("Server variable requires a string default")
            value = value.replace("{" + name + "}", variable["default"])
        if "{" in value or "}" in value:
            raise ValueError("Unresolved API server variable")
        result.append(urljoin(base, value))
    return result


def parse(source: str, documents: dict[str, dict]) -> dict:
    spec = documents[source]
    version = spec.get("openapi", spec.get("swagger", ""))
    if not isinstance(version, str) or not (version == "2.0" or re.fullmatch(r"3\.[01]\.\d+", version)):
        raise ValueError("Supported specifications: OpenAPI 3.0/3.1 and Swagger 2.0")
    if not isinstance(spec.get("paths", {}), dict):
        raise ValueError("API paths must be an object")
    resolver = Resolver(documents)
    operations, errors, servers = [], [], set()
    queue = [(path, item, "path") for path, item in spec.get("paths", {}).items()]
    queue.extend((path, item, "webhook") for path, item in spec.get("webhooks", {}).items())
    schema_definitions = spec.get("components", {}).get("securitySchemes", spec.get("securityDefinitions", {}))
    while queue:
        path, raw, kind = queue.pop(0)
        if not isinstance(path, str) or (kind == "path" and not path.startswith("/")) or not isinstance(raw, dict):
            errors.append(f"Invalid path item: {path}")
            continue
        try:
            item = resolver.resolve(raw, source)
        except ValueError as exc:
            errors.append(f"{path}: {exc}")
            item = raw
        if item.get("resolution") == "unresolved":
            errors.append(f"Unresolved path item: {path}")
        for method, operation in item.items():
            if method not in METHODS:
                continue
            failures_before = set(resolver.failed)
            try:
                if not isinstance(operation, dict):
                    raise ValueError("Operation must be an object")
                operation = resolver.resolve(operation, source)
                parameters = {}
                for parameter in item.get("parameters", []) + operation.get("parameters", []):
                    parameter = resolver.resolve(parameter, source)
                    if parameter.get("resolution") == "unresolved":
                        continue
                    if not isinstance(parameter.get("name"), str) or parameter.get("in") not in {"path", "query", "header", "cookie", "body", "formData"}:
                        raise ValueError("Invalid operation parameter")
                    parameters[(parameter["name"], parameter["in"])] = parameter
                security = operation.get("security", spec.get("security", []))
                if not isinstance(security, list) or not all(isinstance(requirement, dict) for requirement in security):
                    raise ValueError("Invalid security requirements")
                anonymous = not security or {} in security
                if version == "2.0":
                    origin = urlsplit(source)
                    schemes = operation.get("schemes", spec.get("schemes", [origin.scheme or "https"]))
                    urls = [f"{scheme}://{spec.get('host', origin.netloc)}{spec.get('basePath', '/')}" for scheme in schemes]
                else:
                    urls = server_urls(operation.get("servers", item.get("servers", spec.get("servers", [{"url": "/"}]))), source)
                servers.update(urls)
                flags = []
                name = (path + " " + str(operation.get("operationId", ""))).lower()
                for label, tokens in {
                    "administration": ("admin", "management"), "file_transfer": ("upload", "download"),
                    "data_export": ("export",), "identity": ("user", "account"),
                    "financial": ("payment", "invoice"), "ai_inference": ("embedding", "chat", "completion", "inference"),
                    "agent_execution": ("agent", "task", "execute"),
                }.items():
                    if any(token in name for token in tokens):
                        flags.append(label)
                def unresolved(value):
                    if isinstance(value, dict):
                        if value.get("resolution") == "unresolved":
                            yield value["$ref"]
                        for child in value.values():
                            yield from unresolved(child)
                    elif isinstance(value, list):
                        for child in value:
                            yield from unresolved(child)
                failed = sorted(set(unresolved(operation)) | (resolver.failed - failures_before))
                normalized = {"specification": source, "path": path, "method": method.upper(), "kind": kind,
                    "operation_id": operation.get("operationId", ""), "parameters": list(parameters.values()),
                    "request_body": operation.get("requestBody", {}), "responses": operation.get("responses", {}),
                    "security": security, "security_schemes": schema_definitions,
                    "authentication": "not_declared_or_optional" if anonymous else "declared_required",
                    "deprecated": operation.get("deprecated", False), "servers": urls,
                    "consumes": operation.get("consumes", spec.get("consumes", [])),
                    "produces": operation.get("produces", spec.get("produces", [])),
                    "assessment_opportunities": flags, "confidence": 0.9,
                    "validation_status": "unverified", "failed_references": failed}
                normalized["key"] = hashlib.sha256(f"{source}|{kind}|{path}|{method}".encode()).hexdigest()
                operations.append(redact(normalized))
                for callback, mapping in operation.get("callbacks", {}).items():
                    for expression, child in resolver.resolve(mapping, source).items():
                        if expression != "resolution":
                            queue.append((f"{path}::callback:{callback}:{expression}", child, "callback"))
            except (ValueError, TypeError, AttributeError) as exc:
                key = hashlib.sha256(f"{source}|{kind}|{path}|{method}".encode()).hexdigest()
                operations.append({"key": key, "specification": source, "path": path, "method": method.upper(),
                                   "kind": kind, "analysis_error": str(exc), "validation_status": "unverified",
                                   "confidence": 0, "failed_references": sorted(resolver.failed)})
                errors.append(f"{method.upper()} {path}: {exc}")
            if len(operations) >= 10000:
                raise ValueError("Operation inventory exceeds 10,000; coverage incomplete")
    return redact({"source": source, "version": version, "operations": operations, "servers": sorted(servers),
            "errors": errors, "failed_references": sorted(resolver.failed), "paths": len(spec.get("paths", {})),
            "analysis_complete": not errors and not resolver.failed})
