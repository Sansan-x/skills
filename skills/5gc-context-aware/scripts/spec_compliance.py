#!/usr/bin/env python3
"""
Step 4: Spec Compliance Check (规范合规性预检)

Checks the target 5GC codebase against the 3GPP security baseline (TS 33.501)
to identify missing security controls and non-compliant implementations.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional


def load_security_baseline(skill_dir: str) -> dict:
    baseline_path = Path(skill_dir) / "references" / "3gpp_security_baseline.json"
    with open(baseline_path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_code_patterns(project_dir: str, patterns: list[str]) -> list[dict]:
    """Search for specific code patterns across the project."""
    findings = []
    go_files = list(Path(project_dir).rglob("*.go"))

    for go_file in go_files[:500]:
        if "vendor" in str(go_file) or "_test.go" in go_file.name:
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        rel_path = str(go_file.relative_to(project_dir))

        for pattern in patterns:
            if re.search(rf'\b{re.escape(pattern)}\b', content, re.IGNORECASE):
                match = re.search(rf'\b{re.escape(pattern)}\b', content, re.IGNORECASE)
                line_num = content[:match.start()].count("\n") + 1

                context_start = max(0, match.start() - 100)
                context_end = min(len(content), match.end() + 100)
                context = content[context_start:context_end].strip()
                context_lines = context.split("\n")
                context = "\n".join(line.strip() for line in context_lines[:5])

                findings.append({
                    "file": rel_path,
                    "line": line_num,
                    "pattern": pattern,
                    "context_snippet": context[:300]
                })

    return findings


def evaluate_check(project_dir: str, check: dict) -> dict:
    """Evaluate a single compliance check against the codebase."""
    patterns = check.get("code_patterns", [])
    findings = check_code_patterns(project_dir, patterns)

    if findings:
        status = "present"
        confidence = "high" if len(findings) >= 2 else "medium"
    else:
        status = "not_found"
        confidence = "medium"

    return {
        "check_id": check["id"],
        "requirement": check["requirement"],
        "severity": check["severity"],
        "status": status,
        "confidence": confidence,
        "pattern_matches": len(findings),
        "findings": findings[:10],
        "fail_condition": check.get("fail_condition", ""),
        "detection_method": check.get("detection", "")
    }


def check_insecure_patterns(project_dir: str) -> list[dict]:
    """Specifically look for known insecure code patterns."""
    insecure_checks = [
        {
            "id": "INSEC-001",
            "name": "InsecureSkipVerify enabled",
            "pattern": r'InsecureSkipVerify\s*:\s*true',
            "severity": "critical",
            "description": "TLS certificate verification disabled",
            "recommendation": "Remove InsecureSkipVerify or set to false in production code"
        },
        {
            "id": "INSEC-002",
            "name": "Weak TLS version",
            "pattern": r'MinVersion\s*:\s*tls\.VersionTLS10|MinVersion\s*:\s*tls\.VersionSSL',
            "severity": "critical",
            "description": "TLS version below 1.2 configured",
            "recommendation": "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13"
        },
        {
            "id": "INSEC-003",
            "name": "Hardcoded credentials",
            "pattern": r'(?:password|secret|token|apiKey)\s*(?::=|=)\s*"[^"]{4,}"',
            "severity": "critical",
            "description": "Hardcoded credentials or secrets in source code",
            "recommendation": "Move secrets to configuration files or environment variables"
        },
        {
            "id": "INSEC-004",
            "name": "SQL injection risk",
            "pattern": r'(?:db\.(?:Query|Exec)|sql\.Open).*(?:fmt\.Sprintf|string\s*\+)',
            "severity": "high",
            "description": "Possible SQL injection via string concatenation",
            "recommendation": "Use parameterized queries"
        },
        {
            "id": "INSEC-005",
            "name": "Unvalidated type assertion",
            "pattern": r'\.\([\w.*]+\)\s*$',
            "severity": "medium",
            "description": "Type assertion without comma-ok pattern may cause panic",
            "recommendation": "Use val, ok := x.(Type) pattern"
        },
        {
            "id": "INSEC-006",
            "name": "NIA0/NEA0 in non-initial context",
            "pattern": r'(?:NIA0|NEA0|NULL.*[Ii]ntegrity|NULL.*[Cc]ipher)',
            "severity": "critical",
            "description": "NULL security algorithms referenced (may be used after security activation)",
            "recommendation": "Ensure NIA0/NEA0 only used before NAS security activation"
        },
        {
            "id": "INSEC-007",
            "name": "Unchecked error return",
            "pattern": r'(?:Unmarshal|Decode|Read|Write|Close)\([^)]*\)\s*$',
            "severity": "medium",
            "description": "Error return value from critical operation not checked",
            "recommendation": "Always check and handle error returns from I/O and parsing operations"
        },
        {
            "id": "INSEC-008",
            "name": "SUPI in log output",
            "pattern": r'(?:log\.|logger\.|fmt\.Print).*(?:[Ss]upi|[Ii]msi|[Ss]uci)',
            "severity": "high",
            "description": "Subscriber permanent identity may be logged in plaintext",
            "recommendation": "Mask or redact SUPI/IMSI in log outputs"
        }
    ]

    results = []
    go_files = list(Path(project_dir).rglob("*.go"))

    for check in insecure_checks:
        check_findings = []
        for go_file in go_files[:500]:
            if "vendor" in str(go_file) or "_test.go" in go_file.name:
                continue
            try:
                content = go_file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            rel_path = str(go_file.relative_to(project_dir))

            for match in re.finditer(check["pattern"], content, re.MULTILINE):
                line_num = content[:match.start()].count("\n") + 1
                line_content = content.split("\n")[line_num - 1].strip() if line_num > 0 else ""

                if line_content.startswith("//"):
                    continue

                check_findings.append({
                    "file": rel_path,
                    "line": line_num,
                    "matched_text": match.group(0)[:200],
                    "line_content": line_content[:200]
                })

        if check_findings:
            results.append({
                "check_id": check["id"],
                "name": check["name"],
                "severity": check["severity"],
                "description": check["description"],
                "recommendation": check["recommendation"],
                "occurrence_count": len(check_findings),
                "findings": check_findings[:20]
            })

    return results


def run_compliance_check(project_dir: str, skill_dir: str, nf_type: str = "UNKNOWN") -> dict:
    """Main entry point: run all compliance checks."""
    baseline = load_security_baseline(skill_dir)
    compliance_checks = baseline.get("compliance_checks", {})

    relevant_categories = determine_relevant_checks(nf_type)

    results_by_category = {}
    total_checks = 0
    present_count = 0
    not_found_count = 0
    critical_gaps = []

    for category_key, category in compliance_checks.items():
        if relevant_categories and category_key not in relevant_categories:
            continue

        checks = category.get("checks", [])
        category_results = {
            "title": category.get("title", category_key),
            "spec_section": category.get("spec_section", ""),
            "checks": []
        }

        for check in checks:
            result = evaluate_check(project_dir, check)
            category_results["checks"].append(result)
            total_checks += 1

            if result["status"] == "present":
                present_count += 1
            else:
                not_found_count += 1
                if result["severity"] == "critical":
                    critical_gaps.append({
                        "check_id": result["check_id"],
                        "requirement": result["requirement"],
                        "category": category_key
                    })

        results_by_category[category_key] = category_results

    insecure_findings = check_insecure_patterns(project_dir)

    interface_matrix = baseline.get("interface_security_matrix", {})

    return {
        "step": "spec_compliance",
        "project_dir": project_dir,
        "nf_type": nf_type,
        "summary": {
            "total_checks": total_checks,
            "controls_present": present_count,
            "controls_not_found": not_found_count,
            "compliance_rate": round(present_count / max(total_checks, 1) * 100, 1),
            "critical_gaps": len(critical_gaps)
        },
        "critical_gaps": critical_gaps,
        "insecure_patterns": {
            "total_findings": len(insecure_findings),
            "findings": insecure_findings
        },
        "compliance_results": results_by_category,
        "applicable_interface_security": {
            k: v for k, v in interface_matrix.items()
            if is_interface_relevant(k, nf_type, baseline)
        }
    }


def determine_relevant_checks(nf_type: str) -> list[str]:
    """Determine which compliance check categories are relevant for this NF type."""
    nf_check_map = {
        "AMF": ["authentication", "nas_security", "ngap_security", "sbi_security", "subscriber_privacy", "key_management"],
        "SMF": ["sbi_security", "pfcp_security", "key_management"],
        "UPF": ["pfcp_security"],
        "AUSF": ["authentication", "sbi_security", "key_management"],
        "UDM": ["sbi_security", "subscriber_privacy", "key_management"],
        "UDR": ["sbi_security"],
        "NRF": ["sbi_security"],
        "PCF": ["sbi_security"],
        "NSSF": ["sbi_security"],
        "NEF": ["sbi_security"],
    }
    return nf_check_map.get(nf_type, list(nf_check_map.get("AMF", [])))


def is_interface_relevant(interface: str, nf_type: str, baseline: dict) -> bool:
    """Check if a 5GC interface is relevant to the given NF type."""
    nf_interfaces = {
        "AMF": ["N1", "N2", "N8", "N11", "N12", "N14", "N15", "N22"],
        "SMF": ["N4", "N7", "N10", "N11", "N16"],
        "UPF": ["N3", "N4", "N6", "N9"],
        "AUSF": ["N12", "N13"],
        "UDM": ["N8", "N10", "N13"],
        "UDR": ["N35", "N36"],
        "NRF": ["N27"],
        "PCF": ["N7", "N15"],
        "NSSF": ["N22"],
    }
    return interface in nf_interfaces.get(nf_type, [])


def main():
    if len(sys.argv) < 2:
        print("Usage: python spec_compliance.py <project_dir> [skill_dir] [nf_type]")
        sys.exit(1)

    project_dir = sys.argv[1]
    skill_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent.parent)
    nf_type = sys.argv[3] if len(sys.argv) > 3 else "UNKNOWN"

    result = run_compliance_check(project_dir, skill_dir, nf_type)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
