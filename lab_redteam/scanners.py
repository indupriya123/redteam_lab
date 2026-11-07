import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

NMAP_SKILL = {
    "id": "nmap-tcp-discovery",
    "purpose": "Discover open TCP ports inside immutable engagement scope and select bounded follow-up checks.",
    "inputs": ["explicit approved IPs", "explicit approved TCP ports", "operator-approved installed Nmap version"],
    "outputs": ["normalized open ports", "version and binary hash", "scope-validation evidence"],
    "limits": {"maximum_tcp_scope_pairs": 128, "maximum_http_followup_requests": 32},
    "excluded": ["NSE scripts", "OS/version probes", "UDP", "credential use", "arbitrary CLI arguments"],
}

TOOLS = [
    ("garak", "NVIDIA/garak", "LLM assessment", "garak"),
    ("pyrit", "microsoft/PyRIT", "AI campaign orchestration", "pyrit"),
    ("promptfoo", "promptfoo/promptfoo", "LLM/RAG evaluation", "promptfoo"),
    ("deepteam", "confident-ai/deepteam", "LLM/agent assessment", "deepteam"),
    ("giskard", "Giskard-AI/giskard", "RAG/LLM evaluation", "giskard"),
    ("ai-infra-guard", "Tencent/AI-Infra-Guard", "AI infrastructure", "ai-infra-guard"),
    ("purplellama", "meta-llama/PurpleLlama", "Model benchmarking", None),
    ("cisco-mcp-scanner", "cisco-ai-defense/mcp-scanner", "MCP assessment", "mcp-scanner"),
    ("cisco-skill-scanner", "cisco-ai-defense/cisco-ai-skill-scanner", "Skill supply chain", "skill-scanner"),
    ("cisco-a2a-scanner", "cisco-ai-defense/a2a-scanner", "A2A assessment", "a2a-scanner"),
    ("snyk-agent-scan", "snyk/agent-scan", "Agent supply chain", "agent-scan"),
    ("agentic-radar", "splx-ai/agentic-radar", "Agent architecture", "agentic-radar"),
    ("agentdojo", "ethz-spylab/agentdojo", "Agent benchmark", None),
    ("harmbench", "centerforaisafety/HarmBench", "Model benchmark", None),
    ("jailbreakbench", "JailbreakBench/jailbreakbench", "Model benchmark", None),
    ("art", "Trusted-AI/adversarial-robustness-toolbox", "ML robustness", None),
    ("foolbox", "bethgelab/foolbox", "ML robustness", None),
    ("modelscan", "protectai/modelscan", "Model artifacts", "modelscan"),
    ("fickling", "trailofbits/fickling", "Pickle analysis", "fickling"),
    ("picklescan", "mmaitre314/picklescan", "Pickle analysis", "picklescan"),
    ("safetensors", "huggingface/safetensors", "Model packaging", None),
    ("semgrep", "semgrep/semgrep", "Code analysis", "semgrep"),
    ("gitleaks", "gitleaks/gitleaks", "Secret detection", "gitleaks"),
    ("trivy", "aquasecurity/trivy", "Supply chain/configuration", "trivy"),
    ("checkov", "bridgecrewio/checkov", "IaC configuration", "checkov"),
    ("prowler", "prowler-cloud/prowler", "Cloud posture", "prowler"),
    ("kube-bench", "aquasecurity/kube-bench", "Kubernetes posture", "kube-bench"),
    ("nuclei", "projectdiscovery/nuclei", "Curated HTTP checks", "nuclei"),
    ("zap", "zaproxy/zaproxy", "Web/API assessment", "zap.sh"),
    ("codeql", "github/codeql", "Semantic code analysis", "codeql"),
    ("nmap", "nmap/nmap", "Bounded TCP discovery", "nmap"),
]


def registry(approved_version: str, nmap_version: str = "") -> list[dict]:
    result = []
    for name, repository, domain, executable in TOOLS:
        installed = bool(executable and shutil.which(executable))
        version = nmap_version if name == "nmap" else approved_version if name == "nuclei" else ""
        adapter = {"nuclei": "curated_head_only", "nmap": "bounded_tcp_connect"}.get(name)
        result.append({
            "id": name, "repository": repository, "domain": domain,
            "cli_detected": installed, "cli_detection_is_not_full_install_validation": True,
            "adapter": adapter,
            "status": (
                "ready_for_version_validation" if installed and version else
                "requires_installation_and_version_approval"
            ) if adapter else "reference_only_adapter_pending",
            "approved_version": version if adapter else None,
            "limitations": (
                "One bundled HEAD-only template; no arbitrary templates or CLI arguments."
                if name == "nuclei" else "Only approved IP/port pairs; TCP connect discovery, no scripts or service probes."
                if name == "nmap" else
                "No executable adapter yet. An IP does not supply source, artifacts, identities, or benchmark fixtures."
            ),
        })
    return result


async def bounded_command(arguments: list[str], directory: Path, environment: dict[str, str],
                          timeout: int = 20) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *arguments, cwd=directory, env=environment, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )

    async def read(stream: asyncio.StreamReader | None) -> bytes:
        if stream is None:
            raise ValueError("Scanner output pipe missing")
        data = bytearray()
        while chunk := await stream.read(4096):
            data.extend(chunk)
            if len(data) > 65536:
                raise ValueError("Scanner output exceeded 64 KiB")
        return bytes(data)

    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await asyncio.gather(read(process.stdout), read(process.stderr))
            code = await process.wait()
            return code, stdout, stderr
    except BaseException:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise


class NucleiAdapter:
    def __init__(self, approved_version: str):
        self.approved_version = approved_version.removeprefix("v")
        self.slot = asyncio.Semaphore(1)

    async def assess(self, url: str) -> dict:
        if not self.approved_version:
            raise ValueError("Set LAB_NUCLEI_VERSION to the operator-approved installed version")
        executable = shutil.which("nuclei")
        if not executable:
            raise ValueError("Nuclei is not installed; no scanner test performed")
        async with self.slot:
            with tempfile.TemporaryDirectory(prefix="lab-nuclei-") as name:
                directory = Path(name)
                environment = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": name,
                    "XDG_CONFIG_HOME": name, "TMPDIR": name, "NO_COLOR": "1",
                }
                code, out, err = await bounded_command(
                    [executable, "-version"], directory, environment, timeout=5,
                )
                match = re.search(rb"(?:Version:\s*)?v(\d+\.\d+\.\d+)", out + err)
                if code or not match:
                    raise ValueError("Could not validate scanner version")
                version = match.group(1).decode()
                if version != self.approved_version:
                    raise ValueError("Installed scanner version differs from operator-approved version")
                if version.split(".")[0] not in {"2", "3"}:
                    raise ValueError("No validated command profile for this scanner major version")
                template = Path(__file__).resolve().parent / "templates" / "missing-nosniff.yaml"
                template_bytes = template.read_bytes()
                copied_template = directory / "check.yaml"
                copied_template.write_bytes(template_bytes)
                config = directory / "config.yaml"
                config.write_text("{}\n")
                arguments = [
                    executable, "-u", url, "-t", str(copied_template),
                    "-config", str(config), "-config-directory", name,
                    "-jsonl", "-omit-raw", "-silent", "-no-stdin",
                    "-disable-update-check", "-no-interactsh", "-disable-redirects",
                    "-rate-limit", "1", "-concurrency", "1", "-bulk-size", "1",
                    "-timeout", "3", "-retries", "0",
                ]
                code, out, _ = await bounded_command(arguments, directory, environment)
                if code:
                    raise ValueError(f"Scanner exited with status {code}; results are incomplete")
                matches = []
                for line in out.splitlines():
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("Scanner record is not an object")
                    if record.get("template-id") != "lab-missing-nosniff":
                        raise ValueError("Scanner emitted a result outside the curated template")
                    matched = record.get("matched-at", record.get("matched"))
                    if not isinstance(matched, str) or matched.rstrip("/") != url.rstrip("/"):
                        raise ValueError("Scanner result does not match the approved target URL")
                    matches.append({"template_id": record["template-id"], "matched_at": url})
                return {
                    "test": "Curated Nuclei HEAD check", "url": url, "tool": "nuclei",
                    "version": version,
                    "binary_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                    "template_sha256": hashlib.sha256(template_bytes).hexdigest(),
                    "matches": matches, "raw_request_response_collected": False,
                    "result_status": "scanner_alert" if matches else "no_match_inconclusive",
                }


class NmapAdapter:
    def __init__(self, approved_version: str):
        self.approved_version = approved_version

    @staticmethod
    def parse_output(data: bytes, targets: list[str], ports: list[int], version: str) -> dict:
        if b"<!ENTITY" in data or b" SYSTEM " in data or b" PUBLIC " in data:
            raise ValueError("Nmap XML entity declarations are prohibited")
        root = ET.fromstring(data)
        if root.tag != "nmaprun" or root.get("scanner") != "nmap" or root.get("version") != version:
            raise ValueError("Unexpected Nmap XML scanner/version")
        finished = root.find("runstats/finished")
        if finished is None or finished.get("exit") != "success":
            raise ValueError("Nmap did not report a successful scan completion")
        info = root.find("scaninfo")
        if info is None or info.get("type") != "connect" or info.get("protocol") != "tcp":
            raise ValueError("Nmap output is outside the TCP-connect profile")
        reported = set()
        for value in info.get("services", "").split(","):
            parts = value.split("-")
            if len(parts) == 1:
                reported.add(int(parts[0]))
            elif len(parts) == 2:
                start, end = map(int, parts)
                if not 0 <= end - start < 64:
                    raise ValueError("Nmap reported an oversized port range")
                reported.update(range(start, end + 1))
            else:
                raise ValueError("Invalid reported port range")
        if reported != set(ports):
            raise ValueError("Nmap reported scanning ports outside the approved list")
        open_ports = []
        observed_targets = set()
        incomplete_targets = []
        for host in root.findall("host"):
            addresses = [item.get("addr") for item in host.findall("address") if item.get("addrtype") in {"ipv4", "ipv6"}]
            if len(addresses) != 1:
                raise ValueError("Nmap reported a host outside the approved target list")
            target = str(ipaddress.ip_address(addresses[0]))
            if target not in targets:
                raise ValueError("Nmap reported a host outside the approved target list")
            if target in observed_targets:
                raise ValueError("Duplicate target in Nmap output")
            observed_targets.add(target)
            if host.get("timedout") == "true" or host.find("ports") is None:
                incomplete_targets.append(target)
            seen_ports = set()
            for port in host.findall("ports/port"):
                port_id = int(port.get("portid", "0"))
                if port.get("protocol") != "tcp" or port_id not in ports:
                    raise ValueError("Nmap result contains an unapproved port/protocol")
                if port_id in seen_ports:
                    raise ValueError("Nmap reported a duplicate port")
                seen_ports.add(port_id)
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    open_ports.append({"target": target, "port": port_id, "protocol": "tcp",
                                       "state": "open", "application_protocol": "unverified"})
        return {"open_ports": open_ports, "observed_targets": sorted(observed_targets),
                "incomplete_targets": sorted(incomplete_targets),
                "targets_not_reported": sorted(set(targets) - observed_targets)}

    async def discover(self, targets: list[str], ports: list[int]) -> dict:
        if not self.approved_version:
            raise ValueError("Configure LAB_NMAP_VERSION before approving discovery")
        executable = shutil.which("nmap")
        if not executable:
            raise ValueError("Nmap is not installed; TCP discovery was not performed")
        if len(targets) * len(ports) > 128 or not targets or not ports:
            raise ValueError("TCP discovery exceeds its 128-pair scope budget")
        families = {ipaddress.ip_address(target).version for target in targets}
        if len(families) != 1:
            raise ValueError("Use separate Nmap engagements for IPv4 and IPv6 targets")
        with tempfile.TemporaryDirectory(prefix="lab-nmap-") as name:
            directory = Path(name)
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": name, "TMPDIR": name}
            code, out, err = await bounded_command([executable, "--version"], directory, environment, timeout=5)
            match = re.search(rb"Nmap version ([0-9]+\.[0-9]+[A-Za-z0-9._-]*)", out + err)
            if code or not match or match.group(1).decode() != self.approved_version:
                raise ValueError("Installed Nmap version does not match operator approval")
            if self.approved_version.split(".")[0] != "7":
                raise ValueError("No supported command profile for this Nmap major version")
            arguments = [
                executable, "--unprivileged", "-sT", "-Pn", "-n", "--disable-arp-ping",
                "-p", ",".join(str(port) for port in sorted(ports)), "-oX", "-",
                "--max-parallelism", "1", "--max-hostgroup", "1",
                "--max-rate", "2", "--scan-delay", "500ms", "--max-retries", "0",
                "--host-timeout", "45s", "--max-rtt-timeout", "2s",
            ]
            if families == {6}:
                arguments.append("-6")
            arguments.extend(targets)
            code, out, _ = await bounded_command(arguments, directory, environment, timeout=180)
            if code:
                raise ValueError(f"Nmap exited with status {code}; discovery is incomplete")
            parsed = self.parse_output(out, targets, ports, self.approved_version)
            return {
                "test": "Nmap TCP discovery", "tool": "nmap", "skill_id": NMAP_SKILL["id"],
                "version": self.approved_version,
                "binary_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                "xml_sha256": hashlib.sha256(out).hexdigest(),
                "approved_targets": targets, "approved_ports": ports, **parsed,
                "raw_xml_retained": False,
                "limitations": "Connect-scan port state is not a vulnerability. No retries; missed ports are possible. Host discovery is assumed, not proved.",
            }
