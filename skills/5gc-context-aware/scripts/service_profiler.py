#!/usr/bin/env python3
"""
Step 1: Service Profiling (服务画像)

Identifies which 5GC Network Function (NF) the target Go project implements
by analyzing go.mod, configuration files, initialization code, and import patterns.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional


def load_nf_signatures(skill_dir: str) -> dict:
    sig_path = Path(skill_dir) / "references" / "nf_signatures.json"
    with open(sig_path, "r", encoding="utf-8") as f:
        return json.load(f)


def scan_go_mod(project_dir: str) -> dict:
    """Extract module name, dependencies, and potential NF hints from go.mod."""
    go_mod_path = Path(project_dir) / "go.mod"
    result = {"module": "", "dependencies": [], "nf_hints": []}

    if not go_mod_path.exists():
        return result

    content = go_mod_path.read_text(encoding="utf-8")
    module_match = re.search(r"^module\s+(.+)$", content, re.MULTILINE)
    if module_match:
        result["module"] = module_match.group(1).strip()

    require_block = re.findall(
        r"require\s*\((.*?)\)", content, re.DOTALL
    )
    for block in require_block:
        deps = re.findall(r"^\s*(\S+)\s+(\S+)", block, re.MULTILINE)
        result["dependencies"].extend(
            {"path": d[0], "version": d[1]} for d in deps
        )

    single_requires = re.findall(
        r"^require\s+(\S+)\s+(\S+)$", content, re.MULTILINE
    )
    result["dependencies"].extend(
        {"path": d[0], "version": d[1]} for d in single_requires
    )

    return result


def scan_config_files(project_dir: str) -> list[dict]:
    """Scan YAML/JSON config files for nfType and NF-specific fields."""
    config_patterns = ["*.yaml", "*.yml", "*.json", "*.toml"]
    config_dirs = ["config", "configs", "cfg", "deploy", ".", "test", "testdata"]
    findings = []

    for config_dir_name in config_dirs:
        config_dir = Path(project_dir) / config_dir_name
        if not config_dir.is_dir():
            continue

        for pattern in config_patterns:
            for config_file in config_dir.glob(pattern):
                if config_file.stat().st_size > 1_000_000:
                    continue
                try:
                    content = config_file.read_text(encoding="utf-8")
                except (UnicodeDecodeError, PermissionError):
                    continue

                nf_type_match = re.search(
                    r"(?:nfType|nf_type|NFType)\s*[:=]\s*[\"']?(\w+)",
                    content, re.IGNORECASE
                )
                if nf_type_match:
                    findings.append({
                        "file": str(config_file.relative_to(project_dir)),
                        "field": "nfType",
                        "value": nf_type_match.group(1),
                        "confidence": "high"
                    })

                for nf_name in ["amf", "smf", "upf", "nrf", "ausf", "udm", "udr", "pcf", "nssf", "nef"]:
                    name_match = re.search(
                        rf"(?:{nf_name}Name|{nf_name}_name)\s*[:=]\s*[\"']?(\w+)",
                        content, re.IGNORECASE
                    )
                    if name_match:
                        findings.append({
                            "file": str(config_file.relative_to(project_dir)),
                            "field": f"{nf_name}Name",
                            "value": name_match.group(1),
                            "confidence": "medium"
                        })

    return findings


def scan_init_code(project_dir: str, nf_signatures: dict) -> list[dict]:
    """Scan Go source files for NF initialization patterns."""
    findings = []
    go_files = list(Path(project_dir).rglob("*.go"))

    init_patterns = {}
    for nf_type, sig in nf_signatures["nf_types"].items():
        for pattern in sig.get("init_function_patterns", []):
            init_patterns[pattern] = nf_type

    import_patterns = {}
    for nf_type, sig in nf_signatures["nf_types"].items():
        for imp in sig.get("key_imports", []):
            import_patterns[imp] = nf_type

    for go_file in go_files[:500]:
        if "vendor" in str(go_file) or "test" in go_file.name.lower():
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        for pattern, nf_type in init_patterns.items():
            if re.search(pattern, content):
                findings.append({
                    "file": str(go_file.relative_to(project_dir)),
                    "type": "init_function",
                    "pattern": pattern,
                    "nf_type": nf_type,
                    "confidence": "high"
                })

        import_block = re.findall(r'import\s*\((.*?)\)', content, re.DOTALL)
        import_single = re.findall(r'import\s+"([^"]+)"', content)
        all_imports = " ".join(import_block) + " " + " ".join(import_single)

        for imp_pattern, nf_type in import_patterns.items():
            if imp_pattern in all_imports:
                findings.append({
                    "file": str(go_file.relative_to(project_dir)),
                    "type": "key_import",
                    "pattern": imp_pattern,
                    "nf_type": nf_type,
                    "confidence": "medium"
                })

    return findings


def scan_module_name(module_name: str, nf_signatures: dict) -> Optional[dict]:
    """Check if the Go module name matches known NF patterns."""
    for nf_type, sig in nf_signatures["nf_types"].items():
        for pattern in sig.get("go_module_patterns", []):
            if re.search(pattern, module_name, re.IGNORECASE):
                return {
                    "nf_type": nf_type,
                    "match_pattern": pattern,
                    "confidence": "high"
                }
    return None


def determine_nf_type(
    module_result: Optional[dict],
    config_findings: list[dict],
    init_findings: list[dict]
) -> dict:
    """Score and determine the most likely NF type from all evidence."""
    scores: dict[str, float] = {}
    evidence: dict[str, list] = {}

    def add_evidence(nf_type: str, score: float, source: str):
        scores[nf_type] = scores.get(nf_type, 0) + score
        evidence.setdefault(nf_type, []).append(source)

    if module_result:
        add_evidence(
            module_result["nf_type"], 10.0,
            f"go.mod module pattern: {module_result['match_pattern']}"
        )

    for finding in config_findings:
        nf_upper = finding["value"].upper()
        score = 8.0 if finding["confidence"] == "high" else 4.0
        add_evidence(nf_upper, score, f"config:{finding['file']}:{finding['field']}={finding['value']}")

    for finding in init_findings:
        score = 6.0 if finding["confidence"] == "high" else 3.0
        add_evidence(finding["nf_type"], score, f"code:{finding['file']}:{finding['type']}:{finding['pattern']}")

    if not scores:
        return {
            "nf_type": "UNKNOWN",
            "confidence": 0.0,
            "evidence": [],
            "all_scores": {}
        }

    best_nf = max(scores, key=lambda k: scores[k])
    total_score = sum(scores.values())
    confidence = min(scores[best_nf] / max(total_score, 1) * 100, 100)

    return {
        "nf_type": best_nf,
        "confidence": round(confidence, 1),
        "score": scores[best_nf],
        "evidence": evidence.get(best_nf, []),
        "all_scores": {k: round(v, 1) for k, v in sorted(scores.items(), key=lambda x: -x[1])}
    }


def profile_service(project_dir: str, skill_dir: str) -> dict:
    """Main entry point: profile the target 5GC project."""
    nf_signatures = load_nf_signatures(skill_dir)

    go_mod_info = scan_go_mod(project_dir)
    config_findings = scan_config_files(project_dir)
    init_findings = scan_init_code(project_dir, nf_signatures)

    module_match = None
    if go_mod_info["module"]:
        module_match = scan_module_name(go_mod_info["module"], nf_signatures)

    determination = determine_nf_type(module_match, config_findings, init_findings)

    nf_type = determination["nf_type"]
    nf_info = nf_signatures["nf_types"].get(nf_type, {})

    return {
        "step": "service_profiling",
        "project_dir": project_dir,
        "go_module": go_mod_info["module"],
        "dependency_count": len(go_mod_info["dependencies"]),
        "identified_nf": {
            "type": nf_type,
            "full_name": nf_info.get("full_name", "Unknown"),
            "confidence": determination["confidence"],
            "interfaces": nf_info.get("interfaces", []),
            "protocols": nf_info.get("protocols", []),
            "sbi_services": nf_info.get("sbi_service_names", [])
        },
        "evidence": {
            "module_match": module_match,
            "config_findings": config_findings,
            "init_findings_count": len(init_findings),
            "init_findings_summary": init_findings[:10],
            "all_scores": determination["all_scores"]
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python service_profiler.py <project_dir> [skill_dir]")
        sys.exit(1)

    project_dir = sys.argv[1]
    skill_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent.parent)

    result = profile_service(project_dir, skill_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
