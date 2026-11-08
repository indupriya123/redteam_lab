import asyncio
import ipaddress
import socket
from urllib.parse import unquote, urlsplit, urlunsplit


def normalized_url(value: str) -> str:
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query:
        raise ValueError("Discovery URLs require HTTP(S), a host, and no credentials/query")
    if len(value) > 2000 or any(ord(char) < 33 for char in value) or "\\" in value:
        raise ValueError("Invalid discovery URL")
    host = url.hostname.lower().rstrip(".")
    host = f"[{host}]" if ":" in host else host
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid discovery port")
    path = url.path or "/"
    if unquote(unquote(path)) != unquote(path):
        raise ValueError("Double-encoded paths are prohibited")
    if any(part in {".", ".."} for part in unquote(path).split("/")):
        raise ValueError("Ambiguous URL path is prohibited")
    return urlunsplit((url.scheme, f"{host}:{port}", path, "", ""))


class URLScope:
    def __init__(self, settings, urls: list[str], exclusions: list[str] = ()):
        self.settings = settings
        self.origins = set()
        self.exclusions = tuple(exclusions)
        for value in urls:
            normalized = normalized_url(value)
            host = urlsplit(normalized).hostname
            try:
                ipaddress.ip_address(host)
            except ValueError:
                settings.domain(host)
            else:
                settings.ip(host)
            self.origins.add(urlsplit(normalized)[:2])

    def check(self, value: str) -> str:
        normalized = normalized_url(value)
        url = urlsplit(normalized)
        if url[:2] not in self.origins:
            raise ValueError("URL origin outside immutable assessment scope")
        decoded = urlunsplit((url.scheme, url.netloc, unquote(url.path), "", ""))
        if excluded(url.hostname, self.exclusions) or any(
            exclusion.startswith(("http://", "https://")) and decoded.startswith(normalized_url(exclusion))
            for exclusion in self.exclusions
        ):
            raise ValueError("URL is excluded from assessment")
        return normalized

    async def pin(self, value: str) -> tuple[str, str, str]:
        normalized = self.check(value)
        url = urlsplit(normalized)
        host = url.hostname
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            self.settings.domain(host)
            async with asyncio.timeout(10):
                answers = await asyncio.get_running_loop().getaddrinfo(host, url.port, type=socket.SOCK_STREAM)
            addresses = sorted({answer[4][0] for answer in answers})
            if not addresses or len(addresses) > self.settings.max_targets:
                raise ValueError("DNS address count outside configured limit")
            for address in addresses:
                self.settings.ip(address)
                if excluded(address, self.exclusions):
                    raise ValueError("Resolved address is excluded")
            address = addresses[0]
        else:
            self.settings.ip(address)
        if excluded(address, self.exclusions):
            raise ValueError("Pinned address is excluded")
        authority = f"[{address}]:{url.port}" if ":" in address else f"{address}:{url.port}"
        return urlunsplit((url.scheme, authority, url.path, "", "")), url.netloc, host


def excluded(value: str, exclusions) -> bool:
    for exclusion in exclusions:
        if exclusion.startswith(("http://", "https://")):
            continue
        try:
            network = ipaddress.ip_network(exclusion, strict=True)
            address = ipaddress.ip_address(value)
        except ValueError:
            if value.lower().rstrip(".") == exclusion.lower().rstrip(".") or value.lower().rstrip(".").endswith("." + exclusion.lower().rstrip(".")):
                return True
        else:
            if address in network:
                return True
    return False
