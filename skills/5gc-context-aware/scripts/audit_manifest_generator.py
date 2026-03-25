#!/usr/bin/env python3
"""
Audit Manifest Generator (审计导航清单生成器)

Orchestrates all four steps of the 5GC-Context-Aware analysis and produces:
1. A go-audit integration payload (project_context + audit_focus)
2. A detailed internal audit manifest for advanced analysis
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from .service_profiler import profile_service
    from .interface_mapper import map_interfaces
    from .asset_tagger import scan_project_assets
    from .spec_compliance import run_compliance_check
except ImportError:
    from service_profiler import profile_service
    from interface_mapper import map_interfaces
    from asset_tagger import scan_project_assets
    from spec_compliance import run_compliance_check


def load_attack_patterns(skill_dir: str) -> dict:
    patterns_path = Path(skill_dir) / "references" / "attack_patterns.json"
    with open(patterns_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_interface_specs(skill_dir: str) -> dict:
    spec_path = Path(skill_dir) / "references" / "interface_specs.json"
    with open(spec_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_sensitive_assets_ref(skill_dir: str) -> dict:
    asset_path = Path(skill_dir) / "references" / "sensitive_assets.json"
    with open(asset_path, "r", encoding="utf-8") as f:
        return json.load(f)


def determine_security_level(compliance: dict, asset_tags: dict) -> str:
    """Determine overall security level based on analysis results."""
    critical_gaps = compliance.get("summary", {}).get("critical_gaps", 0)
    compliance_rate = compliance.get("summary", {}).get("compliance_rate", 0)
    insecure_count = compliance.get("insecure_patterns", {}).get("total_findings", 0)
    critical_assets = sum(
        1 for a in asset_tags.get("sensitive_assets", [])
        if a.get("sensitivity") == "critical"
    )

    if critical_gaps > 3 or compliance_rate < 40 or insecure_count > 5:
        return "Critical"
    elif critical_gaps > 0 or compliance_rate < 70 or critical_assets > 20:
        return "High"
    elif compliance_rate < 90:
        return "Medium"
    return "Low"


def extract_critical_interfaces(service_profile: dict, interface_map: dict) -> list[str]:
    """Extract the most security-critical interfaces based on analysis."""
    interfaces = service_profile.get("identified_nf", {}).get("interfaces", [])

    interface_priority = {
        "N1": 10, "N2": 9, "N4": 10, "N3": 8, "N11": 7,
        "N12": 8, "N13": 8, "N7": 6, "N14": 7, "N8": 6,
        "N9": 7, "N6": 5, "N27": 6, "N10": 5, "N15": 5,
        "N22": 4, "N16": 4, "N35": 3, "N36": 3, "N29": 3, "N33": 3
    }

    scored = [(iface, interface_priority.get(iface, 1)) for iface in interfaces]
    scored.sort(key=lambda x: -x[1])

    return [iface for iface, _ in scored[:5]]


def build_audit_focus_from_attack_patterns(
    nf_type: str,
    interface_map: dict,
    asset_tags: dict,
    attack_patterns: dict,
    interface_specs: dict,
    sensitive_ref: dict
) -> list[dict]:
    """Build audit_focus items from attack patterns with business risk and taint context."""
    focus_items = []

    common = attack_patterns.get("common_patterns", [])
    nf_specific = attack_patterns.get("nf_specific_patterns", {}).get(nf_type, [])
    all_patterns = nf_specific + common

    for pattern in all_patterns:
        focus = {
            "scope": pattern.get("scope", pattern["id"]),
            "pattern_id": pattern["id"],
            "severity": pattern["severity"],
            "business_risk": pattern.get("business_risk", pattern["description"]),
            "cwe": pattern.get("cwe", []),
            "audit_focus": pattern.get("audit_focus", ""),
            "detection_hints": pattern.get("detection_hints", [])
        }

        taint_sources = pattern.get("taint_sources", [])
        if taint_sources:
            focus["taint_sources"] = taint_sources

        expected_sanitizers = pattern.get("expected_sanitizers", [])
        if expected_sanitizers:
            focus["expected_sanitizers"] = expected_sanitizers

        if pattern.get("spec_reference"):
            focus["spec_reference"] = pattern["spec_reference"]

        target_funcs = find_target_functions(pattern, interface_map)
        if target_funcs:
            focus["target_func"] = target_funcs[0]
            if len(target_funcs) > 1:
                focus["related_funcs"] = target_funcs[1:]

        target_files = find_target_files(pattern, interface_map, asset_tags)
        if target_files:
            focus["target_files"] = target_files

        focus_items.append(focus)

    return focus_items


def build_audit_focus_from_protocol_handlers(
    interface_map: dict,
    interface_specs: dict
) -> list[dict]:
    """Build audit_focus items from discovered protocol handlers."""
    focus_items = []
    proto_specs = interface_specs.get("binary_protocol_handlers", {})

    for proto, handlers in interface_map.get("protocol_handlers", {}).get("handlers", {}).items():
        spec_info = proto_specs.get(proto, {})
        proc_map = {
            p["name"]: p
            for p in spec_info.get("critical_procedures", [])
        }

        for handler in handlers:
            if not handler.get("is_handler"):
                continue

            proc_name = handler["procedure"]
            proc_info = proc_map.get(proc_name, {})

            focus = {
                "scope": f"{proto}_Handler_{proc_name}",
                "target_func": handler["function"],
                "target_files": [f"{handler['file']}:{handler.get('line_approx', 0)}"],
                "protocol": proto,
                "severity": "high",
                "business_risk": proc_info.get("business_risk", proc_info.get("security", f"{proto}协议处理函数安全审计")),
                "audit_focus": f"Review {proto} {proc_name} handler for input validation and security checks"
            }

            if proc_info.get("taint_sources"):
                focus["taint_sources"] = proc_info["taint_sources"]
            if proc_info.get("expected_sanitizers"):
                focus["expected_sanitizers"] = proc_info["expected_sanitizers"]

            focus_items.append(focus)

    return focus_items


def build_audit_focus_from_sbi_routes(
    interface_map: dict,
    interface_specs: dict
) -> list[dict]:
    """Build audit_focus items from discovered SBI routes."""
    focus_items = []

    for route in interface_map.get("sbi_routes", {}).get("routes", []):
        sbi = route.get("sbi_service")
        if not sbi or not sbi.get("security_critical"):
            continue

        service_name = sbi.get("service", "unknown")
        operation = sbi.get("operation", "unknown")

        focus = {
            "scope": f"SBI_{service_name}_{operation}".replace("/", "_").replace("{", "").replace("}", ""),
            "target_files": [f"{route['file']}:{route.get('line_approx', 0)}"],
            "method": route.get("method", ""),
            "path": route.get("path", ""),
            "severity": "high",
            "business_risk": f"SBI接口{service_name}操作{operation}未经授权访问可导致核心网服务被滥用",
            "taint_sources": [f"c.Request.Body", f"c.Param(\"*\")", "c.GetHeader(\"Authorization\")"],
            "expected_sanitizers": ["VerifyAccessToken", "ValidateRequestBody", "CheckNFAuthorization"],
            "audit_focus": sbi.get("audit_notes", f"Verify authorization on {service_name} {operation}")
        }

        focus_items.append(focus)

    return focus_items


def build_audit_focus_from_sensitive_vars(
    asset_tags: dict,
    sensitive_ref: dict
) -> list[dict]:
    """Build audit_focus items from discovered sensitive variables and structs."""
    focus_items = []
    processed_categories = set()

    for asset in asset_tags.get("sensitive_assets", []):
        category = asset.get("category", "")
        if category in processed_categories or category == "sensitive_struct":
            continue

        cat_ref = sensitive_ref.get(category, {})
        if not cat_ref or not isinstance(cat_ref, dict):
            continue

        processed_categories.add(category)

        matching_assets = [
            a for a in asset_tags.get("sensitive_assets", [])
            if a.get("category") == category
        ]

        target_vars = list(set(a["name"] for a in matching_assets[:5]))
        target_files = list(set(
            f"{a['file']}:{a['line']}" for a in matching_assets[:5]
        ))

        focus = {
            "scope": f"Sensitive_Data_{category}",
            "target_var": ", ".join(target_vars),
            "target_files": target_files,
            "severity": "critical" if cat_ref.get("sensitivity") == "critical" else "high",
            "business_risk": cat_ref.get("business_risk", f"{category}数据泄露风险"),
            "audit_focus": f"Track data flow of {category} variables to ensure no unauthorized exposure"
        }

        if cat_ref.get("taint_sinks"):
            focus["taint_sinks"] = cat_ref["taint_sinks"]
        if cat_ref.get("expected_sanitizers"):
            focus["expected_sanitizers"] = cat_ref["expected_sanitizers"]

        focus_items.append(focus)

    for asset in asset_tags.get("sensitive_assets", []):
        if asset.get("category") != "sensitive_struct":
            continue

        focus_items.append({
            "scope": f"Sensitive_Struct_{asset['name']}",
            "target_var": asset["name"],
            "target_files": [f"{asset['file']}:{asset['line']}"],
            "severity": "critical",
            "business_risk": asset.get("description", "") + "，" + (asset.get("business_risk", "包含敏感数据的结构体需要严格的并发控制和生命周期管理") if "business_risk" in asset else "结构体包含聚合敏感数据"),
            "contains_sensitive": asset.get("contains", []),
            "expected_sanitizers": asset.get("expected_sanitizers", ["LockBeforeAccess", "ClearOnRelease"]),
            "audit_focus": f"Verify {asset['name']} struct has proper mutex protection, lifecycle cleanup, and no direct serialization"
        })

    return focus_items


def build_audit_focus_from_compliance_gaps(compliance: dict) -> list[dict]:
    """Build audit_focus items from compliance gaps."""
    focus_items = []

    for gap in compliance.get("critical_gaps", []):
        focus_items.append({
            "scope": f"Compliance_Gap_{gap['check_id']}",
            "check_id": gap["check_id"],
            "severity": "critical",
            "business_risk": f"3GPP规范合规缺失: {gap['requirement']}",
            "category": gap["category"],
            "audit_focus": f"Verify if {gap['requirement']} is implemented, possibly in a different code path"
        })

    for finding in compliance.get("insecure_patterns", {}).get("findings", []):
        target_files = [
            f"{f['file']}:{f['line']}"
            for f in finding.get("findings", [])[:5]
        ]
        focus_items.append({
            "scope": f"Insecure_Pattern_{finding['check_id']}",
            "check_id": finding["check_id"],
            "severity": finding["severity"],
            "business_risk": finding["description"],
            "target_files": target_files,
            "occurrence_count": finding.get("occurrence_count", 0),
            "audit_focus": finding.get("recommendation", "Review and remediate"),
            "expected_sanitizers": [finding.get("recommendation", "Fix insecure pattern")]
        })

    return focus_items


def find_target_functions(pattern: dict, interface_map: dict) -> list[str]:
    """Find actual function names in the project that match a pattern's detection hints."""
    functions = []
    hints = set(pattern.get("detection_hints", []))

    for proto, handlers in interface_map.get("protocol_handlers", {}).get("handlers", {}).items():
        for handler in handlers:
            func_name = handler.get("function", "")
            proc_name = handler.get("procedure", "")
            if any(h in func_name or h in proc_name for h in hints):
                functions.append(func_name)

    return list(set(functions))[:3]


def find_target_files(pattern: dict, interface_map: dict, asset_tags: dict) -> list[str]:
    """Find files relevant to an attack pattern."""
    files = set()
    hints = set(pattern.get("detection_hints", []))

    for proto, handlers in interface_map.get("protocol_handlers", {}).get("handlers", {}).items():
        for handler in handlers:
            if any(h in handler.get("function", "") or h in handler.get("procedure", "") for h in hints):
                files.add(f"{handler['file']}:{handler.get('line_approx', 0)}")

    for route in interface_map.get("sbi_routes", {}).get("routes", []):
        path = route.get("path", "")
        if any(h.lower() in path.lower() for h in hints):
            files.add(f"{route['file']}:{route.get('line_approx', 0)}")

    return list(files)[:5]


def build_go_audit_payload(
    service_profile: dict,
    interface_map: dict,
    asset_tags: dict,
    compliance: dict,
    attack_patterns: dict,
    interface_specs: dict,
    sensitive_ref: dict
) -> dict:
    """Build the go-audit integration payload: project_context + audit_focus."""
    nf_type = service_profile["identified_nf"]["type"]

    project_context = {
        "nf_type": nf_type,
        "nf_full_name": service_profile["identified_nf"]["full_name"],
        "go_module": service_profile["go_module"],
        "confidence": service_profile["identified_nf"]["confidence"],
        "critical_interfaces": extract_critical_interfaces(service_profile, interface_map),
        "protocols": service_profile["identified_nf"]["protocols"],
        "sbi_services": service_profile["identified_nf"]["sbi_services"],
        "security_level": determine_security_level(compliance, asset_tags),
        "http_framework": interface_map["http_framework"]["framework"],
        "stats": {
            "sbi_routes": interface_map["sbi_routes"]["total"],
            "security_critical_routes": interface_map["sbi_routes"]["security_critical"],
            "protocol_handlers": interface_map["protocol_handlers"]["by_protocol"],
            "auth_middleware_count": interface_map["auth_middleware"]["total"],
            "sensitive_assets_tagged": asset_tags["total_tags"],
            "compliance_rate": compliance["summary"]["compliance_rate"],
            "critical_gaps": compliance["summary"]["critical_gaps"],
            "insecure_patterns": compliance["insecure_patterns"]["total_findings"]
        }
    }

    audit_focus = []

    attack_focus = build_audit_focus_from_attack_patterns(
        nf_type, interface_map, asset_tags, attack_patterns, interface_specs, sensitive_ref
    )
    audit_focus.extend(attack_focus)

    proto_focus = build_audit_focus_from_protocol_handlers(interface_map, interface_specs)
    audit_focus.extend(proto_focus)

    sbi_focus = build_audit_focus_from_sbi_routes(interface_map, interface_specs)
    audit_focus.extend(sbi_focus)

    asset_focus = build_audit_focus_from_sensitive_vars(asset_tags, sensitive_ref)
    audit_focus.extend(asset_focus)

    compliance_focus = build_audit_focus_from_compliance_gaps(compliance)
    audit_focus.extend(compliance_focus)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    audit_focus.sort(key=lambda x: severity_order.get(x.get("severity", "medium"), 2))

    return {
        "project_context": project_context,
        "audit_focus": audit_focus
    }


def severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)


def generate_audit_manifest(project_dir: str, skill_dir: str) -> dict:
    """Main orchestrator: run all 4 steps and generate both go-audit payload and detailed manifest."""
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

    print("[Building] go-audit integration payload...", file=sys.stderr)
    attack_patterns = load_attack_patterns(skill_dir)
    interface_specs = load_interface_specs(skill_dir)
    sensitive_ref = load_sensitive_assets_ref(skill_dir)

    go_audit_payload = build_go_audit_payload(
        service_profile, interface_map, asset_tags, compliance,
        attack_patterns, interface_specs, sensitive_ref
    )

    elapsed = round(time.time() - start_time, 2)

    print(f"  -> Generated {len(go_audit_payload['audit_focus'])} audit focus items", file=sys.stderr)
    print(f"  -> Security level: {go_audit_payload['project_context']['security_level']}",
          file=sys.stderr)

    manifest = {
        "version": "2.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_time_seconds": elapsed,

        "go_audit_payload": go_audit_payload,

        "detailed_results": {
            "service_profiling": service_profile,
            "interface_mapping": interface_map,
            "asset_tagging": asset_tags,
            "spec_compliance": compliance
        }
    }

    print(f"\n[Done] Audit manifest generated in {elapsed}s", file=sys.stderr)
    return manifest


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.audit_manifest_generator <project_dir> [skill_dir]")
        print("   or: python audit_manifest_generator.py <project_dir> [skill_dir]")
        sys.exit(1)

    project_dir = sys.argv[1]
    skill_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent.parent)

    manifest = generate_audit_manifest(project_dir, skill_dir)

    manifest_path = Path(project_dir) / "audit_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"\nFull manifest saved to: {manifest_path}", file=sys.stderr)

    payload_path = Path(project_dir) / "go_audit_payload.json"
    with open(payload_path, "w", encoding="utf-8") as f:
        json.dump(manifest["go_audit_payload"], f, indent=2, ensure_ascii=False)
    print(f"go-audit payload saved to: {payload_path}", file=sys.stderr)

    print(json.dumps(manifest["go_audit_payload"], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
