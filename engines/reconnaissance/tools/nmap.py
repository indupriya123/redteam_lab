import asyncio
import hashlib
import ipaddress
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from ..config.settings import Settings
from ..database.store import timestamp

STATES = {"open", "closed", "filtered", "open|filtered", "closed|filtered", "unfiltered"}


async def command(arguments: list[str], directory: Path, timeout: int) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *arguments, cwd=directory, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(directory)},
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )

    async def read(stream):
        result = bytearray()
        while chunk := await stream.read(8192):
            result.extend(chunk)
            if len(result) > 2 * 1024 * 1024:
                raise ValueError("Nmap output limit exceeded")
        return bytes(result)

    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await asyncio.gather(read(process.stdout), read(process.stderr))
            return await process.wait(), stdout, stderr
    except BaseException:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise


def port_set(value: str) -> set[int]:
    result = set()
    for section in value.split(","):
        if not section:
            continue
        pieces = section.split("-")
        start = int(pieces[0])
        end = int(pieces[-1])
        if len(pieces) > 2 or not 1 <= start <= end <= 65535:
            raise ValueError("Invalid Nmap port range")
        result.update(range(start, end + 1))
    return result


def parse_batch(data: bytes, target: str, protocol: str, ports: list[int], version: str) -> list[dict]:
    if b"<!ENTITY" in data or b" SYSTEM " in data or b" PUBLIC " in data:
        raise ValueError("XML entity declarations are prohibited")
    root = ET.fromstring(data)
    if root.tag != "nmaprun" or root.get("scanner") != "nmap" or root.get("version") != version:
        raise ValueError("Unexpected Nmap scanner/version")
    info = root.find("scaninfo")
    expected_type = "connect" if protocol == "tcp" else "udp"
    if info is None or info.get("type") != expected_type or info.get("protocol") != protocol or port_set(info.get("services", "")) != set(ports):
        raise ValueError("Nmap scan profile or port scope mismatch")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap batch did not complete successfully")
    host = None
    for candidate in root.findall("host"):
        addresses = [item.get("addr") for item in candidate.findall("address") if item.get("addrtype") in {"ipv4", "ipv6"}]
        if len(addresses) != 1 or str(ipaddress.ip_address(addresses[0])) != target or host is not None:
            raise ValueError("Nmap host outside approved scope")
        host = candidate
    records = {port: {
        "target": target, "port": port, "protocol": protocol, "state": "unknown",
        "service": "unknown", "product": "", "version": "", "fingerprint_confidence": 0,
        "evidence_refs": [], "timestamp": timestamp(), "assessment_status": "incomplete",
    } for port in ports}
    if host is None or host.get("timedout") == "true":
        return list(records.values())
    seen = set()
    for item in host.findall("ports/port"):
        port = int(item.get("portid", "0"))
        if port not in records or item.get("protocol") != protocol or port in seen:
            raise ValueError("Nmap returned duplicate/unapproved port")
        seen.add(port)
        state = item.find("state")
        if state is None or state.get("state") not in STATES:
            continue
        records[port].update(state=state.get("state"), assessment_status="completed")
        service = item.find("service")
        if service is not None:
            probed = service.get("method") == "probed"
            confidence = min(1, max(0, int(service.get("conf", "0")) / 10)) if probed else 0.3
            records[port].update(service=service.get("name", "unknown")[:120],
                                 product=service.get("product", "")[:200] if probed else "",
                                 version=service.get("version", "")[:120] if probed else "",
                                 fingerprint_confidence=confidence,
                                 fingerprint_basis="service_probe" if probed else "unverified_port_table_hint")
            if service.get("tunnel") == "ssl":
                records[port]["tunnel"] = "ssl"
    remaining = set(ports) - seen
    extras = host.findall("ports/extraports")
    for extra in extras:
        state = extra.get("state")
        if state not in STATES - {"open"}:
            continue
        described = set()
        for reason in extra.findall("extrareasons"):
            described.update(port_set(reason.get("ports", "")))
        if described:
            if not described <= remaining or len(described) != int(extra.get("count", "0")):
                raise ValueError("Aggregate Nmap port evidence contradicts scope")
        elif len(extras) == 1 and int(extra.get("count", "0")) == len(remaining):
            described = remaining.copy()
        for port in described:
            records[port].update(state=state, assessment_status="completed", state_basis="nmap_aggregate")
        remaining -= described
    return list(records.values())


class NmapWorker:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def batch(self, target: str, protocol: str, ports: list[int], fingerprint: bool) -> tuple[list[dict], dict]:
        self.settings.ip(target)
        if protocol not in {"tcp", "udp"} or not ports or len(ports) > self.settings.batch_size or ports != list(range(ports[0], ports[-1] + 1)) or not 1 <= ports[0] <= ports[-1] <= 65535:
            raise ValueError("Batch must be a bounded contiguous approved TCP/UDP port range")
        if not self.settings.nmap_version:
            raise ValueError("Operator-approved Nmap version missing")
        executable = shutil.which("nmap")
        if not executable:
            raise ValueError("Nmap is unavailable; discovery cannot be completed")
        if protocol == "udp" and (not self.settings.enable_udp or os.geteuid() != 0):
            raise ValueError("UDP execution is not permitted in this deployment")
        with tempfile.TemporaryDirectory(prefix="recon-nmap-") as name:
            directory = Path(name)
            code, out, err = await command([executable, "--version"], directory, 5)
            match = re.search(rb"Nmap version ([0-9]+\.[0-9]+[A-Za-z0-9._-]*)", out + err)
            if code or not match or match.group(1).decode() != self.settings.nmap_version:
                raise ValueError("Nmap version differs from approved configuration")
            arguments = [executable, "-sT" if protocol == "tcp" else "-sU", "-Pn", "-n",
                         "--disable-arp-ping", "-p", f"{ports[0]}-{ports[-1]}", "-oX", "-",
                         "--max-rate", str(self.settings.scan_rate), "--max-parallelism", str(self.settings.max_parallelism),
                         "--max-retries", "1", "--host-timeout", "120s", "--max-rtt-timeout", "2s"]
            if protocol == "tcp":
                arguments.append("--unprivileged")
            if ":" in target:
                arguments.append("-6")
            if fingerprint:
                arguments.extend(["-sV", "--version-light"])
            arguments.append(target)
            code, xml, _ = await command(arguments, directory, self.settings.command_timeout)
            if code:
                raise ValueError(f"Nmap failed with exit status {code}")
            records = parse_batch(xml, target, protocol, ports, self.settings.nmap_version)
            observation = {
                "target": target, "protocol": protocol, "port_range": [ports[0], ports[-1]],
                "version": self.settings.nmap_version, "xml_sha256": hashlib.sha256(xml).hexdigest(),
                "binary_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                "state_counts": dict(Counter(item["state"] for item in records)),
                "profile": "connect" if protocol == "tcp" else "udp", "service_probes": fingerprint,
                "native_version_category_scripts_may_run": fingerprint,
                "raw_xml_retained": False,
            }
            return records, observation
