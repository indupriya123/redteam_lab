import asyncio
import ipaddress
import socket

from ..config.settings import Settings


async def resolve(targets: list[str], settings: Settings) -> tuple[list[str], list[dict]]:
    addresses = []
    intelligence = []
    for target in targets:
        if "/" in target:
            if ipaddress.ip_network(target).num_addresses > settings.max_targets:
                raise ValueError("CIDR exceeds configured execution limit")
            addresses.extend(settings.ip(str(address)) for address in ipaddress.ip_network(target).hosts())
            if len(set(addresses)) > settings.max_targets:
                raise ValueError("Resolved addresses exceed approved engagement limit")
            continue
        try:
            ipaddress.ip_address(target)
        except ValueError:
            domain = settings.domain(target)
            async with asyncio.timeout(10):
                results = await asyncio.get_running_loop().getaddrinfo(domain, None, type=socket.SOCK_STREAM)
            resolved = sorted({result[4][0] for result in results})
            if not resolved:
                raise ValueError(f"No DNS address available for {domain}")
            approved = [settings.ip(value) for value in resolved]
            addresses.extend(approved)
            intelligence.append({"domain": domain, "addresses": approved, "source": "operator-host DNS resolver"})
        else:
            addresses.append(settings.ip(target))
        if len(set(addresses)) > settings.max_targets:
            raise ValueError("Resolved addresses exceed approved engagement limit")
    return sorted(set(addresses)), intelligence
