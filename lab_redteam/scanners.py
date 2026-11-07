import asyncio
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

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
]


def registry(approved_version: str) -> list[dict]:
    result = []
    for name, repository, domain, executable in TOOLS:
        installed = bool(executable and shutil.which(executable))
        result.append({
            "id": name, "repository": repository, "domain": domain,
            "cli_detected": installed, "cli_detection_is_not_full_install_validation": True,
            "adapter": "curated_head_only" if name == "nuclei" else None,
            "status": (
                "ready_for_version_validation" if installed and approved_version else
                "requires_installation_and_version_approval"
            ) if name == "nuclei" else "reference_only_adapter_pending",
            "approved_version": approved_version if name == "nuclei" else None,
            "limitations": (
                "One bundled HEAD-only template; no arbitrary templates or CLI arguments."
                if name == "nuclei" else
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
