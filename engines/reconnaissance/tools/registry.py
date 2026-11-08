import importlib.metadata
import shutil


def describe(settings):
    implemented = {
        "nmap": ("native_full_port", settings.nmap_version, "bounded TCP/UDP scan batches"),
        "system-dns": ("scoped_resolution", "", "A/AAAA resolution only"),
        "httpx": ("pinned_read_only_http", importlib.metadata.version("httpx"), "GET metadata under approved URL origins"),
        "openapi-parser": ("json_yaml_reference_parser", "1", "OpenAPI 3.0/3.1, Swagger 2.0 operation analysis"),
        "bloodhound-export": ("customer_json_analysis", "1", "Export ingestion only; no live collection or credential attacks"),
        "sbom-parser": ("customer_sbom_analysis", "1", "CycloneDX/SPDX packages; no live CVE attribution"),
    }
    external = ("masscan", "rustscan", "nc", "traceroute", "tcpdump", "tshark", "amass", "subfinder", "dnsx",
                "fierce", "theHarvester", "gau", "waybackurls", "whatweb", "katana", "hakrawler", "gospider",
                "gobuster", "feroxbuster", "ffuf", "nikto", "nuclei", "ldapsearch", "netexec", "ldapdomaindump",
                "enum4linux-ng", "certipy", "sharphound", "pingcastle", "adexplorer", "trivy", "prowler")
    results = []
    for name in list(implemented) + list(external):
        adapter, version, description = implemented.get(name, (None, "", "No execution adapter in this engine"))
        native = name == "nmap" or name in external
        executable = shutil.which(name) if native else None
        results.append({"name": name, "category": "reconnaissance", "description": description,
                        "version": version, "installation_status": "detected" if executable or not native else "unavailable",
                        "availability": bool(executable) if native else True, "supported_os": ["linux", "darwin"],
                        "dependencies": ["operator scope and authorization"], "execution_adapter": adapter,
                        "input_schema": {"type": "object"}, "output_schema": {"type": "object"},
                        "timeout_seconds": settings.command_timeout if name == "nmap" else 10,
                        "concurrency": 1, "risk": "active_discovery" if name in {"nmap", "httpx", "system-dns"} else "offline_analysis",
                        "required_permissions": ["explicit_scope", "operator_approval"],
                        "profiles": [adapter] if adapter else [],
                        "status": "adapter_available_native_golden_pending" if name == "nmap" else "implemented_adapter" if adapter else "adapter_not_implemented"})
    return results
