import hashlib
import json

from .openapi import document, redact


def ingest_exports(store, identifier: str, mode: str, supplied: list):
    identities = {}
    pending = []
    for source in supplied:
        if source.format not in {"bloodhound", "cyclonedx", "spdx"}:
            continue
        execution = store.execution_start(identifier, "identity_discovery" if source.format == "bloodhound" else "ai_supply_chain",
                                          "customer_export_analysis", source.format, source.source_reference)
        try:
            data = document(source.content)
            evidence = store.capture(identifier, source.source_reference, mode, {
                "format": source.format, "sha256": hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest(),
                "basis": "customer_export_assertions_not_live_validation", "raw_content_retained": False,
            })
            if source.format == "bloodhound":
                entries = data.get("data")
                if not isinstance(entries, list) or len(entries) > 5000:
                    raise ValueError("BloodHound export requires at most 5,000 data objects")
                kind = data.get("meta", {}).get("type", "unknown")
                for entry in entries:
                    if not isinstance(entry, dict) or not isinstance(entry.get("ObjectIdentifier"), str):
                        raise ValueError("BloodHound object requires ObjectIdentifier")
                    key = entry["ObjectIdentifier"]
                    props = entry.get("Properties", {})
                    if not isinstance(props, dict) or any(
                        not isinstance(entry.get(name, []), list) or not all(isinstance(item, dict) for item in entry.get(name, []))
                        for name in ("Aces", "Members")
                    ):
                        raise ValueError("Invalid BloodHound properties or relationship arrays")
                    attrs = redact({"object_id": key, "object_type": kind, "display_name": props.get("name", key),
                                    "domain": props.get("domain", ""), "enabled": props.get("enabled"),
                                    "basis": "BloodHound_export_not_current_privilege_validation"})
                    node = store.asset(identifier, "identity", key, evidence, attrs, inferred=True, confidence=0.7)
                    identities[key] = node
                    store.record(identifier, "ad_object", key, attrs, source.source_reference, [evidence], "source_asserted")
                    pending.append((node, entry, evidence))
            else:
                entries = data.get("components") if source.format == "cyclonedx" else data.get("packages")
                if not isinstance(entries, list) or len(entries) > 5000:
                    raise ValueError("SBOM requires at most 5,000 components/packages")
                if source.format == "cyclonedx" and data.get("bomFormat") != "CycloneDX":
                    raise ValueError("Expected CycloneDX SBOM")
                if source.format == "spdx" and not str(data.get("spdxVersion", "")).startswith("SPDX-"):
                    raise ValueError("Expected SPDX SBOM")
                refs = {}
                for entry in entries:
                    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                        raise ValueError("SBOM component requires name")
                    version = entry.get("version", entry.get("versionInfo", "unknown"))
                    key = entry.get("bom-ref", entry.get("SPDXID", f"{entry['name']}@{version}"))
                    attrs = {"name": entry["name"], "version": str(version), "package_url": entry.get("purl", ""),
                             "basis": "customer_SBOM_not_package_or_CVE_validation"}
                    node = store.asset(identifier, "dependency", f"{entry['name']}@{version}", evidence, attrs,
                                       inferred=True, confidence=0.8)
                    refs[key] = node
                    store.record(identifier, "supply_chain_component", str(key), attrs, source.source_reference, [evidence],
                                 "source_asserted")
                relationships = data.get("dependencies", []) if source.format == "cyclonedx" else []
                for item in relationships:
                    for dependency in item.get("dependsOn", []):
                        if item.get("ref") in refs and dependency in refs:
                            store.edge(identifier, refs[item["ref"]], refs[dependency], "depends_on", evidence, True, 0.8)
            store.execution_finish(execution, "completed", [evidence])
        except (ValueError, TypeError, AttributeError) as exc:
            store.execution_finish(execution, "failed", error=str(exc))
            store.event(identifier, "export_discovery", "Export analysis failed", {"source": source.name, "error": str(exc)})
    for node, entry, evidence in pending:
        for ace in entry.get("Aces", []):
            principal = identities.get(ace.get("PrincipalSID"))
            if principal and isinstance(ace.get("RightName"), str):
                store.edge(identifier, principal, node, "source_asserted_permission:" + ace["RightName"], evidence, True, 0.7)
        for member in entry.get("Members", []):
            child = identities.get(member.get("ObjectIdentifier"))
            if child:
                store.edge(identifier, child, node, "member_of", evidence, True, 0.7)
