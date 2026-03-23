#!/usr/bin/env python3
"""
Audit Manifest Generator (审计导航清单生成器)

Orchestrates all four steps of the 5GC-Context-Aware analysis and produces
a unified Audit Manifest that guides downstream taint analysis and code review.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .service_profiler import profile_service
from .interface_mapper import map_interfaces
from .asset_tagger import scan_project_assets
from .spec_compliance import run_compliance_check


def load_attack_patterns(skill_dir: str) -> dict:
    patterns_path = Path(skill_dir) / "references" / "attack_patterns.json"
    with open(patterns_path, "r", encoding="utf-8") as f:
        return json.load(f)


def correlate_with_attack_patterns(
    nf_type: str,
    interface_map: dict,
    asset_tags: dict,
    attack_patterns: dict
) -> list[dict]:
    """Cross-reference discovered interfaces and assets with known attack patterns."""
    correlations = []

    common = attack_patterns.get("common_patterns", [])
    nf_specific = attack_patterns.get("nf_specific_patterns", {}).get(nf_type, [])
    all_patterns = common + nf_specific

    tagged_files = set()
    for asset in asset_tags.get("sensitive_assets", []):
        tagged_files.add(asset.get("file", ""))

    route_files = set()
    for route in interface_map.get("sbi_routes", {}).get("routes", []):
        route_files.add(route.get("file", ""))

    handler_files = set()
    for proto, handlers in interface_map.get("protocol_handlers", {}).get("handlers", {}).items():
        for handler in handlers:
            handler_files.add(handler.get("file", ""))

    for pattern in all_patterns:
        relevant_files = set()

        for hint in pattern.get("detection_hints", []):
            for f in tagged_files | route_files | handler_files:
                if f:
                    relevant_files.add(f)

        priority_score = calculate_priority(pattern, interface_map, asset_tags)

        correlations.append({
            "pattern_id": pattern["id"],
            "name": pattern["name"],
            "severity": pattern["severity"],
            "cwe": pattern.get("cwe", []),
            "audit_focus": pattern.get("audit_focus", ""),
            "detection_hints": pattern.get("detection_hints", []),
            "spec_reference": pattern.get("spec_reference", ""),
            "priority_score": priority_score,
            "suggested_files": list(relevant_files)[:20]
        })

    correlations.sort(key=lambda x: (-severity_rank(x["severity"]), -x["priority_score"]))
    return correlations


def calculate_priority(pattern: dict, interface_map: dict, asset_tags: dict) -> float:
    """Calculate a priority score for an attack pattern based on project context."""
    score = 0.0

    severity_scores = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}
    score += severity_scores.get(pattern.get("severity", "medium"), 4.0)

    hints = pattern.get("detection_hints", [])
    for asset in asset_tags.get("sensitive_assets", []):
        if asset.get("sensitivity") == "critical":
            score += 2.0
            break

    proto_handlers = interface_map.get("protocol_handlers", {}).get("handlers", {})
    for proto, handlers in proto_handlers.items():
        if handlers:
            score += 1.0

    sbi_routes = interface_map.get("sbi_routes", {})
    if sbi_routes.get("security_critical", 0) > 0:
        score += 2.0

    return round(score, 1)


def severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)


def generate_taint_analysis_directives(
    nf_type: str,
    asset_tags: dict,
    interface_map: dict,
    compliance: dict
) -> list[dict]:
    """Generate specific directives for downstream taint analysis engines."""
    directives = []

    for asset in asset_tags.get("sensitive_assets", []):
        if asset.get("sensitivity") == "critical":
            directives.append({
                "type": "taint_source",
                "target": f"{asset['file']}:{asset['line']}",
                "variable": asset["name"],
                "category": asset["category"],
                "description": f"Track flow of {asset['description']} ({asset['name']})",
                "sink_types": ["log_output", "network_send", "file_write", "error_response"]
            })

    for route in interface_map.get("sbi_routes", {}).get("routes", []):
        sbi = route.get("sbi_service")
        if sbi and sbi.get("security_critical"):
            directives.append({
                "type": "entry_point",
                "target": f"{route['file']}:{route.get('line_approx', 0)}",
                "path": route.get("path", ""),
                "method": route.get("method", ""),
                "description": f"SBI entry: {sbi.get('service', '')} - {sbi.get('operation', '')}",
                "check_auth": True,
                "check_input_validation": True
            })

    for proto, handlers in interface_map.get("protocol_handlers", {}).get("handlers", {}).items():
        for handler in handlers:
            if handler.get("is_handler"):
                directives.append({
                    "type": "entry_point",
                    "target": f"{handler['file']}:{handler.get('line_approx', 0)}",
                    "protocol": proto,
                    "procedure": handler["procedure"],
                    "function": handler["function"],
                    "description": f"{proto} handler: {handler['procedure']}",
                    "check_input_validation": True,
                    "check_bounds": True,
                    "security_note": handler.get("security_note", "")
                })

    for gap in compliance.get("critical_gaps", []):
        directives.append({
            "type": "compliance_gap",
            "check_id": gap["check_id"],
            "requirement": gap["requirement"],
            "category": gap["category"],
            "description": f"Missing security control: {gap['requirement']}"
        })

    return directives


def generate_audit_manifest(project_dir: str, skill_dir: str) -> dict:
    """Main orchestrator: run all 4 steps and generate the unified Audit Manifest."""
    start_time = time.time()

    print("[Step 1/4] Service Profiling...", file=sys.stderr)
    service_profile = profile_service(project_dir, skill_dir)
    nf_type = service_profile["identified_nf"]["type"]
    print(f"  -> Identified NF: {nf_type} ({service_profile['identified_nf']['full_name']})",
          file=sys.stderr)

    print("[Step 2/4] Interface Mapping...", file=sys.stderr)
    interface_map = map_interfaces(project_dir, skill_dir, nf_type)
    print(f"  -> SBI routes: {interface_map['sbi_routes']['total']}, "
          f"Protocol handlers: {interface_map['protocol_handlers']['total']}",
          file=sys.stderr)

    print("[Step 3/4] Sensitive Asset Tagging...", file=sys.stderr)
    asset_tags = scan_project_assets(project_dir, skill_dir)
    print(f"  -> Tagged {asset_tags['total_tags']} sensitive assets in "
          f"{asset_tags['files_scanned']} files", file=sys.stderr)

    print("[Step 4/4] Spec Compliance Check...", file=sys.stderr)
    compliance = run_compliance_check(project_dir, skill_dir, nf_type)
    print(f"  -> Compliance rate: {compliance['summary']['compliance_rate']}%, "
          f"Critical gaps: {compliance['summary']['critical_gaps']}", file=sys.stderr)

    print("[Correlating] Attack pattern analysis...", file=sys.stderr)
    attack_patterns = load_attack_patterns(skill_dir)
    correlations = correlate_with_attack_patterns(
        nf_type, interface_map, asset_tags, attack_patterns
    )

    print("[Generating] Taint analysis directives...", file=sys.stderr)
    taint_directives = generate_taint_analysis_directives(
        nf_type, asset_tags, interface_map, compliance
    )

    elapsed = round(time.time() - start_time, 2)

    manifest = {
        "audit_manifest": {
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analysis_time_seconds": elapsed,
            "project_dir": project_dir,

            "service_profile": {
                "nf_type": nf_type,
                "full_name": service_profile["identified_nf"]["full_name"],
                "confidence": service_profile["identified_nf"]["confidence"],
                "go_module": service_profile["go_module"],
                "interfaces": service_profile["identified_nf"]["interfaces"],
                "protocols": service_profile["identified_nf"]["protocols"],
                "sbi_services": service_profile["identified_nf"]["sbi_services"]
            },

            "interface_map": {
                "http_framework": interface_map["http_framework"],
                "sbi_route_count": interface_map["sbi_routes"]["total"],
                "security_critical_routes": interface_map["sbi_routes"]["security_critical"],
                "protocol_handler_counts": interface_map["protocol_handlers"]["by_protocol"],
                "auth_middleware_count": interface_map["auth_middleware"]["total"],
                "coverage_warnings": interface_map["coverage_warnings"]
            },

            "sensitive_assets": {
                "total_tagged": asset_tags["total_tags"],
                "files_scanned": asset_tags["files_scanned"],
                "category_summary": asset_tags["category_summary"],
                "top_hotspots": asset_tags["top_hotspot_files"]
            },

            "compliance": {
                "summary": compliance["summary"],
                "critical_gaps": compliance["critical_gaps"],
                "insecure_pattern_count": compliance["insecure_patterns"]["total_findings"],
                "insecure_patterns": compliance["insecure_patterns"]["findings"]
            },

            "attack_pattern_correlations": correlations[:30],

            "taint_analysis_directives": taint_directives[:100],

            "audit_priority_queue": build_priority_queue(
                correlations, taint_directives, compliance
            )
        },

        "detailed_results": {
            "service_profiling": service_profile,
            "interface_mapping": interface_map,
            "asset_tagging": asset_tags,
            "spec_compliance": compliance
        }
    }

    print(f"\n[Done] Audit manifest generated in {elapsed}s", file=sys.stderr)
    return manifest


def build_priority_queue(
    correlations: list,
    directives: list,
    compliance: dict
) -> list[dict]:
    """Build a prioritized queue of audit tasks."""
    queue = []

    for gap in compliance.get("critical_gaps", []):
        queue.append({
            "priority": 1,
            "type": "compliance_gap",
            "description": f"[CRITICAL] Missing: {gap['requirement']}",
            "check_id": gap["check_id"],
            "action": "Verify if the security control is implemented elsewhere or truly missing"
        })

    for finding in compliance.get("insecure_patterns", {}).get("findings", []):
        if finding.get("severity") == "critical":
            queue.append({
                "priority": 2,
                "type": "insecure_pattern",
                "description": f"[CRITICAL] {finding['name']}: {finding['description']}",
                "check_id": finding["check_id"],
                "occurrence_count": finding.get("occurrence_count", 0),
                "action": finding.get("recommendation", "Review and fix")
            })

    for corr in correlations[:10]:
        queue.append({
            "priority": 2 if corr["severity"] == "critical" else 3,
            "type": "attack_pattern",
            "description": f"[{corr['severity'].upper()}] {corr['name']}",
            "pattern_id": corr["pattern_id"],
            "cwe": corr["cwe"],
            "action": corr["audit_focus"]
        })

    entry_points = [d for d in directives if d["type"] == "entry_point"]
    for ep in entry_points[:20]:
        queue.append({
            "priority": 3,
            "type": "entry_point_review",
            "description": f"Review entry point: {ep.get('description', '')}",
            "target": ep.get("target", ""),
            "action": "Perform taint analysis from this entry point"
        })

    queue.sort(key=lambda x: x["priority"])
    return queue


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.audit_manifest_generator <project_dir> [skill_dir]")
        print("   or: python audit_manifest_generator.py <project_dir> [skill_dir]")
        sys.exit(1)

    project_dir = sys.argv[1]
    skill_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent.parent)

    manifest = generate_audit_manifest(project_dir, skill_dir)

    output_path = Path(project_dir) / "audit_manifest.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"\nAudit manifest saved to: {output_path}", file=sys.stderr)

    summary = manifest["audit_manifest"]
    print(json.dumps({
        "service_profile": summary["service_profile"],
        "interface_map": summary["interface_map"],
        "sensitive_assets": summary["sensitive_assets"],
        "compliance": summary["compliance"],
        "priority_queue_size": len(summary["audit_priority_queue"]),
        "attack_correlations": len(summary["attack_pattern_correlations"]),
        "taint_directives": len(summary["taint_analysis_directives"])
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
