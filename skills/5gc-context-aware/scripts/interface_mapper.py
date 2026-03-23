#!/usr/bin/env python3
"""
Step 2: Interface & Protocol Mapping (接口与协议映射)

Parses RESTful routes (SBI interfaces) and binary protocol handlers (PFCP, NAS, NGAP)
to build a map of all communication interfaces in the target 5GC project.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional


def load_interface_specs(skill_dir: str) -> dict:
    spec_path = Path(skill_dir) / "references" / "interface_specs.json"
    with open(spec_path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_router_framework(project_dir: str) -> dict:
    """Detect which HTTP router framework is used."""
    go_mod_path = Path(project_dir) / "go.mod"
    frameworks = {
        "github.com/gin-gonic/gin": "gin",
        "github.com/labstack/echo": "echo",
        "github.com/gorilla/mux": "gorilla_mux",
    }

    detected = {"framework": "net_http", "evidence": "default (no known framework detected)"}

    if go_mod_path.exists():
        content = go_mod_path.read_text(encoding="utf-8")
        for dep, name in frameworks.items():
            if dep in content:
                detected = {"framework": name, "evidence": f"found in go.mod: {dep}"}
                break

    return detected


def extract_sbi_routes(project_dir: str, interface_specs: dict) -> list[dict]:
    """Extract SBI route registrations from Go source files."""
    routes = []
    go_files = list(Path(project_dir).rglob("*.go"))

    route_patterns = [
        # gin patterns
        r'(?:router|group|r|g|api|v1)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*"([^"]+)"',
        # echo patterns
        r'(?:e|echo|group|g|api)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*"([^"]+)"',
        # gorilla mux
        r'(?:router|r|mux)\s*\.\s*HandleFunc\s*\(\s*"([^"]+)".*?\)\s*\.\s*Methods\s*\(\s*"([^"]+)"',
        # net/http
        r'http\.HandleFunc\s*\(\s*"([^"]+)"',
        # common pattern: group with prefix
        r'(?:router|r|group|g)\s*\.\s*Group\s*\(\s*"([^"]+)"',
        # AddService / RegisterRoutes pattern used in free5gc
        r'(?:Add|Register)(?:Route|Service|Handler)\w*\s*\(\s*"([^"]+)"',
    ]

    group_prefix_pattern = re.compile(
        r'(\w+)\s*(?::=|=)\s*(?:router|r|group|g|api)\s*\.\s*Group\s*\(\s*"([^"]+)"'
    )

    for go_file in go_files[:500]:
        if "vendor" in str(go_file) or "_test.go" in go_file.name:
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        rel_path = str(go_file.relative_to(project_dir))

        groups = {}
        for match in group_prefix_pattern.finditer(content):
            groups[match.group(1)] = match.group(2)

        for pattern in route_patterns:
            for match in re.finditer(pattern, content):
                route_info = {"file": rel_path, "line_approx": content[:match.start()].count("\n") + 1}

                if len(match.groups()) >= 2:
                    route_info["method"] = match.group(1).upper()
                    route_info["path"] = match.group(2)
                elif len(match.groups()) == 1:
                    route_info["path"] = match.group(1)
                    route_info["method"] = "ANY"
                else:
                    continue

                route_info["sbi_service"] = identify_sbi_service(
                    route_info["path"], interface_specs
                )

                routes.append(route_info)

    return routes


def identify_sbi_service(path: str, interface_specs: dict) -> Optional[dict]:
    """Match a route path to a known SBI service API."""
    sbi_apis = interface_specs.get("sbi_api_paths", {})

    for service_name, service_info in sbi_apis.items():
        base_path = service_info.get("base_path", "")
        if base_path and base_path in path:
            for op_path, op_info in service_info.get("operations", {}).items():
                normalized_op = re.sub(r'\{[^}]+\}', ':param', op_path)
                normalized_route = re.sub(r':[^/]+', ':param', path)
                full_op_path = base_path + normalized_op

                if normalized_route.endswith(normalized_op) or full_op_path in path:
                    return {
                        "service": service_name,
                        "operation": op_path,
                        "nf_type": service_info.get("nf_type"),
                        "spec": service_info.get("spec"),
                        "security_critical": op_info.get("security_critical", False),
                        "audit_notes": op_info.get("audit_notes", "")
                    }

            return {
                "service": service_name,
                "operation": "unknown",
                "nf_type": service_info.get("nf_type"),
                "spec": service_info.get("spec"),
                "security_critical": True
            }

    return None


def extract_protocol_handlers(project_dir: str, interface_specs: dict) -> dict:
    """Extract binary protocol message handlers (NGAP, NAS, PFCP, GTP-U)."""
    handlers = {"NGAP": [], "NAS-5G": [], "PFCP": [], "GTP-U": []}
    go_files = list(Path(project_dir).rglob("*.go"))

    binary_protos = interface_specs.get("binary_protocol_handlers", {})

    for go_file in go_files[:500]:
        if "vendor" in str(go_file) or "_test.go" in go_file.name:
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        rel_path = str(go_file.relative_to(project_dir))

        for proto_name, proto_info in binary_protos.items():
            for pkg in proto_info.get("go_packages", []):
                if pkg not in content:
                    continue

                for procedure in proto_info.get("critical_procedures", []):
                    proc_name = procedure["name"]
                    if re.search(rf'\b{proc_name}\b', content):
                        line_match = re.search(rf'\b{proc_name}\b', content)
                        line_num = content[:line_match.start()].count("\n") + 1 if line_match else 0

                        func_match = re.search(
                            rf'func\s+(?:\([^)]+\)\s+)?(\w*{proc_name}\w*)\s*\(',
                            content
                        )
                        func_name = func_match.group(1) if func_match else f"(reference to {proc_name})"

                        handlers[proto_name].append({
                            "file": rel_path,
                            "line_approx": line_num,
                            "procedure": proc_name,
                            "function": func_name,
                            "security_note": procedure.get("security", ""),
                            "is_handler": func_match is not None
                        })
                break

    for proto in handlers:
        seen = set()
        unique = []
        for h in handlers[proto]:
            key = (h["file"], h["procedure"], h["function"])
            if key not in seen:
                seen.add(key)
                unique.append(h)
        handlers[proto] = unique

    return handlers


def extract_middleware(project_dir: str) -> list[dict]:
    """Identify authentication/authorization middleware in HTTP handler chains."""
    middleware = []
    go_files = list(Path(project_dir).rglob("*.go"))

    auth_patterns = [
        (r'func\s+(\w*[Aa]uth\w*)\s*\(', "authentication_middleware"),
        (r'func\s+(\w*[Tt]oken[Vv]alid\w*)\s*\(', "token_validation"),
        (r'func\s+(\w*OAuth\w*)\s*\(', "oauth_handler"),
        (r'func\s+(\w*JWT\w*)\s*\(', "jwt_handler"),
        (r'func\s+(\w*[Mm]TLS\w*)\s*\(', "mtls_handler"),
        (r'\.Use\s*\(\s*(\w*[Aa]uth\w*)', "middleware_registration"),
        (r'\.Use\s*\(\s*(\w*[Tt]oken\w*)', "middleware_registration"),
    ]

    for go_file in go_files[:500]:
        if "vendor" in str(go_file) or "_test.go" in go_file.name:
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        rel_path = str(go_file.relative_to(project_dir))

        for pattern, mw_type in auth_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                middleware.append({
                    "file": rel_path,
                    "line_approx": line_num,
                    "name": match.group(1),
                    "type": mw_type
                })

    return middleware


def map_interfaces(project_dir: str, skill_dir: str, nf_type: str = "UNKNOWN") -> dict:
    """Main entry point: map all interfaces in the target project."""
    interface_specs = load_interface_specs(skill_dir)

    framework = detect_router_framework(project_dir)
    sbi_routes = extract_sbi_routes(project_dir, interface_specs)
    protocol_handlers = extract_protocol_handlers(project_dir, interface_specs)
    middleware = extract_middleware(project_dir)

    security_critical_routes = [r for r in sbi_routes if r.get("sbi_service", {}) and
                                 r.get("sbi_service", {}).get("security_critical")]

    total_handlers = sum(len(v) for v in protocol_handlers.values())

    return {
        "step": "interface_mapping",
        "project_dir": project_dir,
        "nf_type": nf_type,
        "http_framework": framework,
        "sbi_routes": {
            "total": len(sbi_routes),
            "security_critical": len(security_critical_routes),
            "routes": sbi_routes
        },
        "protocol_handlers": {
            "total": total_handlers,
            "by_protocol": {k: len(v) for k, v in protocol_handlers.items()},
            "handlers": protocol_handlers
        },
        "auth_middleware": {
            "total": len(middleware),
            "entries": middleware
        },
        "coverage_warnings": generate_coverage_warnings(
            sbi_routes, protocol_handlers, middleware, nf_type, interface_specs
        )
    }


def generate_coverage_warnings(
    routes: list, handlers: dict, middleware: list,
    nf_type: str, specs: dict
) -> list[dict]:
    """Generate warnings about missing security coverage."""
    warnings = []

    if not middleware:
        warnings.append({
            "severity": "critical",
            "type": "missing_auth_middleware",
            "message": "No authentication/authorization middleware detected in HTTP handler chain",
            "recommendation": "Implement OAuth2 token validation middleware per TS 33.501 Section 13"
        })

    for route in routes:
        sbi = route.get("sbi_service")
        if sbi and sbi.get("security_critical"):
            has_auth = any(
                m["file"] == route["file"] or "middleware" in m["type"]
                for m in middleware
            )
            if not has_auth:
                warnings.append({
                    "severity": "high",
                    "type": "unprotected_critical_route",
                    "message": f"Security-critical route {route.get('path', 'unknown')} may lack auth middleware",
                    "file": route["file"],
                    "recommendation": f"Verify {sbi.get('service', 'unknown')} endpoint has proper authorization"
                })

    proto_specs = specs.get("binary_protocol_handlers", {})
    for proto, proto_info in proto_specs.items():
        expected_critical = [p["name"] for p in proto_info.get("critical_procedures", [])]
        found_procs = {h["procedure"] for h in handlers.get(proto, [])}
        missing = set(expected_critical) - found_procs

        if handlers.get(proto) and missing:
            warnings.append({
                "severity": "medium",
                "type": "missing_protocol_handler",
                "message": f"{proto}: handlers found but missing critical procedures: {', '.join(list(missing)[:5])}",
                "recommendation": f"Verify these {proto} procedures are handled (may be in different packages)"
            })

    return warnings


def main():
    if len(sys.argv) < 2:
        print("Usage: python interface_mapper.py <project_dir> [skill_dir] [nf_type]")
        sys.exit(1)

    project_dir = sys.argv[1]
    skill_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent.parent)
    nf_type = sys.argv[3] if len(sys.argv) > 3 else "UNKNOWN"

    result = map_interfaces(project_dir, skill_dir, nf_type)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
