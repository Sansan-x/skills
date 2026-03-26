#!/usr/bin/env python3
"""
5GC Decompose + Map + Checklist (tree-sitter first, regex fallback)

Outputs (in project root by default):
  - audit_project_map.json
  - audit_checklists.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


GO_KEYWORDS = {
    "if",
    "for",
    "switch",
    "select",
    "case",
    "func",
    "return",
    "go",
    "defer",
    "map",
    "chan",
    "struct",
    "type",
    "var",
    "const",
    "else",
    "break",
    "continue",
    "fallthrough",
    "range",
}


FUNC_RE = re.compile(
    r"func\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{",
    re.MULTILINE,
)

METHOD_RE = re.compile(
    r"func\s*\(\s*(?P<recvname>[A-Za-z_]\w*)\s+(?P<recvtype>\*?[A-Za-z_]\w*)\s*\)\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{",
    re.MULTILINE,
)


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError, PermissionError):
        return None


def _rel(project_dir: Path, p: Path) -> str:
    try:
        return str(p.relative_to(project_dir))
    except ValueError:
        return str(p)


def _is_go_file(p: Path) -> bool:
    return p.suffix == ".go" and not p.name.endswith("_test.go")


def _is_ignored_path(rel_path: str) -> bool:
    lower = rel_path.lower()
    return "vendor/" in lower or lower.endswith("/vendor") or "testdata/" in lower


def _detect_package_name(content: str) -> str:
    m = re.search(r"^\s*package\s+([A-Za-z_]\w*)\s*$", content, re.MULTILINE)
    return m.group(1) if m else "unknown"


def _find_block_end(text: str, start_idx: int) -> int:
    """
    Naive brace matching from the first '{' at/after start_idx.
    Used only for coarse call extraction; failures degrade gracefully.
    """
    open_brace_idx = text.find("{", start_idx)
    if open_brace_idx < 0:
        return min(len(text), start_idx + 2000)
    depth = 0
    i = open_brace_idx
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth <= 0:
                return i + 1
        i += 1
    return len(text)


def _extract_calls_regex(body: str) -> List[str]:
    # captures identifiers before '('
    candidates = re.findall(r"\b([A-Za-z_]\w*)\s*\(", body)
    out: List[str] = []
    for c in candidates:
        if c in GO_KEYWORDS:
            continue
        out.append(c)
    # de-dup but keep order
    seen = set()
    deduped = []
    for c in out:
        if c in seen:
            continue
        seen.add(c)
        deduped.append(c)
    return deduped[:50]


def _extract_functions_regex(project_dir: Path, go_files: List[Path]) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    functions: List[Dict[str, Any]] = []
    func_name_to_ids: Dict[str, List[str]] = {}
    for f in go_files:
        rel_path = _rel(project_dir, f)
        content = _read_text(f)
        if not content:
            continue

        # Methods first
        for m in METHOD_RE.finditer(content):
            name = m.group("name")
            recvtype = m.group("recvtype").lstrip("*")
            params = m.group("params").strip()
            line = content[: m.start()].count("\n") + 1
            body_end = _find_block_end(content, m.end())
            body = content[m.end() : body_end]
            calls = _extract_calls_regex(body)
            func_obj = {
                "kind": "method",
                "name": name,
                "receiver_type": recvtype,
                "file": rel_path,
                "line": line,
                "params_raw": params,
                "calls": calls,
            }
            functions.append(func_obj)
            func_name_to_ids.setdefault(name, []).append(str(len(functions) - 1))

        # Functions
        for m in FUNC_RE.finditer(content):
            name = m.group("name")
            params = m.group("params").strip()
            line = content[: m.start()].count("\n") + 1
            body_end = _find_block_end(content, m.end())
            body = content[m.end() : body_end]
            calls = _extract_calls_regex(body)
            func_obj = {
                "kind": "function",
                "name": name,
                "receiver_type": None,
                "file": rel_path,
                "line": line,
                "params_raw": params,
                "calls": calls,
            }
            functions.append(func_obj)
            func_name_to_ids.setdefault(name, []).append(str(len(functions) - 1))

    # Add stable IDs later.
    return functions, func_name_to_ids


def _init_tree_sitter_go() -> Optional[Any]:
    try:
        from tree_sitter import Parser  # type: ignore
        from tree_sitter_languages import get_language  # type: ignore

        parser = Parser()
        parser.set_language(get_language("go"))
        return parser
    except Exception:
        return None


def _node_text(source_bytes: bytes, node: Any) -> str:
    try:
        return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_functions_tree_sitter(parser: Any, project_dir: Path, go_files: List[Path]) -> List[Dict[str, Any]]:
    functions: List[Dict[str, Any]] = []
    for f in go_files:
        rel_path = _rel(project_dir, f)
        b = f.read_bytes()
        try:
            tree = parser.parse(b)
        except Exception:
            continue

        root = tree.root_node
        stack = [root]
        while stack:
            node = stack.pop()
            try:
                ntype = node.type
            except Exception:
                continue
            if ntype in ("function_declaration", "method_declaration"):
                # Best-effort extraction. Field names differ across versions.
                name_node = node.child_by_field_name("name")
                if not name_node:
                    # Fallback: find first identifier-like child
                    for c in node.children:
                        if getattr(c, "type", "") == "identifier":
                            name_node = c
                            break
                name = _node_text(b, name_node).strip() if name_node else ""

                receiver_type: Optional[str] = None
                if ntype == "method_declaration":
                    recv_node = node.child_by_field_name("receiver")
                    if recv_node:
                        receiver_type = _node_text(b, recv_node).strip()
                    else:
                        # try parsing "*Type" from receiver text
                        for c in node.children:
                            if getattr(c, "type", "") == "parameter_list":
                                continue
                            # leave it as full receiver text best-effort
                        receiver_type = None

                params_raw: Optional[str] = None
                params_node = node.child_by_field_name("parameters")
                if params_node:
                    params_raw = _node_text(b, params_node).strip()

                line = node.start_point[0] + 1

                # Extract calls inside body if possible
                calls: List[str] = []
                body_node = node.child_by_field_name("body")
                if body_node:
                    q = [body_node]
                    call_names: List[str] = []
                    while q:
                        bn = q.pop()
                        btype = getattr(bn, "type", "")
                        if btype == "call_expression":
                            fn_node = bn.child_by_field_name("function")
                            if fn_node:
                                txt = _node_text(b, fn_node).strip()
                                # reduce selector_expression like pkg.Func -> Func
                                if "." in txt:
                                    txt = txt.split(".")[-1]
                                if txt:
                                    call_names.append(txt)
                        for ch in getattr(bn, "children", []) or []:
                            q.append(ch)
                    # de-dup / cap
                    seen = set()
                    for c in call_names:
                        if c in GO_KEYWORDS:
                            continue
                        if c in seen:
                            continue
                        seen.add(c)
                        calls.append(c)
                    calls = calls[:50]

                if name:
                    functions.append(
                        {
                            "kind": "method" if ntype == "method_declaration" else "function",
                            "name": name,
                            "receiver_type": receiver_type,
                            "file": rel_path,
                            "line": line,
                            "params_raw": params_raw,
                            "calls": calls,
                        }
                    )

            # DFS
            for ch in getattr(node, "children", []) or []:
                stack.append(ch)

    return functions


def _build_modules_regex(project_dir: Path, go_files: List[Path]) -> List[Dict[str, Any]]:
    # module = directory containing go files
    dir_map: Dict[str, List[Path]] = {}
    for f in go_files:
        rel = _rel(project_dir, f)
        if _is_ignored_path(rel):
            continue
        rel_dir = str(f.parent.relative_to(project_dir))
        dir_map.setdefault(rel_dir, []).append(f)

    modules: List[Dict[str, Any]] = []
    for rel_dir, files in sorted(dir_map.items(), key=lambda x: x[0]):
        pkg_names: List[str] = []
        sample_pkg = "unknown"
        for pf in files[:3]:
            content = _read_text(pf)
            if not content:
                continue
            sample_pkg = _detect_package_name(content)
            pkg_names.append(sample_pkg)
        modules.append(
            {
                "name": sample_pkg,
                "path": rel_dir,
                "go_files": [_rel(project_dir, f) for f in files[:20]],
                "packages": sorted(list(set(pkg_names)))[:5],
            }
        )
    return modules


def _pick_entry_candidates(functions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    sbi_names = []
    proto_names = []
    for i, fn in enumerate(functions):
        name = fn.get("name", "") or ""
        file_path = fn.get("file", "") or ""
        lower_fp = file_path.lower()

        if (
            ("/sbi/" in lower_fp or "sbi" in lower_fp or "router" in lower_fp or "controller" in lower_fp)
            and re.search(r"(Handle|Process|ServeHTTP|Producer)", name)
        ):
            sbi_names.append(
                {
                    "func_index": i,
                    "kind": "sbi_http_handler",
                    "name": name,
                    "file": file_path,
                    "line": fn.get("line", 0),
                }
            )

        if any(k in name for k in ["PFCP", "Nas", "NAS", "Ngap", "NGAP", "GTP", "gtp"]) or any(
            k in lower_fp for k in ["pfcp", "nas", "ngap", "gtp"]
        ):
            proto_k = "unknown"
            if "pfcp" in lower_fp or "PFCP" in name:
                proto_k = "PFCP"
            elif "ngap" in lower_fp or "NGAP" in name:
                proto_k = "NGAP"
            elif "nas" in lower_fp or "NAS" in name:
                proto_k = "NAS-5G"
            elif "gtp" in lower_fp or "GTP" in name:
                proto_k = "GTP-U"
            proto_names.append(
                {
                    "func_index": i,
                    "kind": proto_k,
                    "name": name,
                    "file": file_path,
                    "line": fn.get("line", 0),
                }
            )

    # cap
    sbi_names = sbi_names[:30]
    proto_names = proto_names[:50]
    return {"sbi_handlers": sbi_names, "protocol_handlers": proto_names}


def _finalize_ids(
    modules: List[Dict[str, Any]], functions: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str]]:
    # Assign IDs deterministically by order
    for mi, m in enumerate(modules):
        m["module_id"] = f"mod-{mi:04d}"
    for fi, fn in enumerate(functions):
        fn["func_id"] = f"fn-{fi:06d}"
    # map func name -> ids
    return modules, functions, {}


def generate(project_dir: Path, skill_dir: Path, output_dir: Path, max_files: int) -> Dict[str, Any]:
    go_files: List[Path] = []
    for p in project_dir.rglob("*.go"):
        if not _is_go_file(p):
            continue
        rel_path = _rel(project_dir, p)
        if _is_ignored_path(rel_path):
            continue
        go_files.append(p)
        if len(go_files) >= max_files:
            break

    modules = _build_modules_regex(project_dir, go_files)

    parser = _init_tree_sitter_go()
    extraction_method: Dict[str, Any] = {}

    if parser is not None:
        functions = _extract_functions_tree_sitter(parser, project_dir, go_files)
        extraction_method["tree_sitter_go"] = "used"
        if not functions:
            extraction_method["tree_sitter_go"] = "used_but_empty"
            extraction_method["call_graph"] = "fallback_regex_calls"
            functions, _ = _extract_functions_regex(project_dir, go_files)
    else:
        functions, _ = _extract_functions_regex(project_dir, go_files)
        extraction_method["tree_sitter_go"] = "not_available"
        extraction_method["call_graph"] = "regex_approx"

    # IDs
    modules, functions, _ = _finalize_ids(modules, functions)

    # Assign functions to modules by file path match
    module_by_path = {m["path"]: m for m in modules}
    for fn in functions:
        rel_dir = str(Path(fn["file"]).parent)
        if rel_dir in module_by_path:
            module_by_path[rel_dir].setdefault("function_ids", []).append(fn["func_id"])

    for m in modules:
        if "function_ids" in m:
            m["function_ids"] = m["function_ids"][:200]

    entry_candidates = _pick_entry_candidates(functions)
    # Convert func_index to func_id
    for key in ["sbi_handlers", "protocol_handlers"]:
        for e in entry_candidates.get(key, []):
            idx = e.get("func_index")
            if isinstance(idx, int) and 0 <= idx < len(functions):
                e["func_id"] = functions[idx]["func_id"]
            e.pop("func_index", None)

    # Call graph edges: coarse by name
    name_to_funcids: Dict[str, List[str]] = {}
    for fn in functions:
        name_to_funcids.setdefault(fn["name"], []).append(fn["func_id"])

    edges: List[Dict[str, Any]] = []
    for fn in functions:
        for called in fn.get("calls", []) or []:
            # resolve to known function IDs when possible
            to_ids = name_to_funcids.get(called, [])
            for tid in to_ids[:3]:
                edges.append({"from": fn["func_id"], "to": tid, "label": called})

    call_graph = {
        "edge_precision": "name_match_coarse",
        "edges": edges[:20000],
        "nodes_count": len(functions),
    }

    # Attach module signals (simple)
    for m in modules:
        p = (m.get("path", "") or "").lower()
        signals = []
        if "/sbi/" in p or "sbi" in p:
            signals.append("has_sbi")
        if "pfcp" in p:
            signals.append("has_pfcp")
        if "nas" in p:
            signals.append("has_nas")
        if "ngap" in p:
            signals.append("has_ngap")
        if "gtp" in p:
            signals.append("has_gtp")
        if not signals:
            signals.append("generic")
        m["module_signals"] = signals[:5]

    project_map = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_dir": str(project_dir),
        "extraction_method": extraction_method,
        "stats": {
            "go_files_scanned": len(go_files),
            "modules_extracted": len(modules),
            "functions_extracted": len(functions),
            "entry_candidates_sbi": len(entry_candidates["sbi_handlers"]),
            "entry_candidates_protocol": len(entry_candidates["protocol_handlers"]),
        },
        "modules": modules,
        "functions": functions,
        "call_graph": call_graph,
        "entry_candidates": entry_candidates,
    }

    checklists_ref_path = skill_dir / "references" / "checklists_5gc.json"
    checklists: Dict[str, Any] = {}
    if checklists_ref_path.exists():
        checklists = json.loads(checklists_ref_path.read_text(encoding="utf-8"))
    else:
        checklists = {
            "version": "1.0",
            "checklist_categories": [],
            "warnings": ["Missing references/checklists_5gc.json; produced empty checklists."],
        }

    audit_checklists = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "skills/5gc-audit-decompose-map-checklist/references/checklists_5gc.json",
        "checklist_categories": checklists.get("checklist_categories", []),
        "category_count": len(checklists.get("checklist_categories", [])),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit_project_map.json").write_text(
        json.dumps(project_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (output_dir / "audit_checklists.json").write_text(
        json.dumps(audit_checklists, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    project_map["output_files"] = {
        "audit_project_map": str(output_dir / "audit_project_map.json"),
        "audit_checklists": str(output_dir / "audit_checklists.json"),
    }
    return project_map


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("project_dir", help="Target 5GC Go project directory")
    ap.add_argument(
        "--skill-dir",
        default=None,
        help="Skill directory root (default: parent of scripts/).",
    )
    ap.add_argument("--output-dir", default=None, help="Where to write outputs (default: project_dir)")
    ap.add_argument("--max-files", type=int, default=1200, help="Max Go files to scan")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).expanduser().resolve()
    if not project_dir.exists() or not project_dir.is_dir():
        print(f"[ERROR] project_dir not found or not a directory: {project_dir}", file=sys.stderr)
        sys.exit(2)

    script_dir = Path(__file__).resolve().parent
    skill_dir = Path(args.skill_dir).expanduser().resolve() if args.skill_dir else script_dir.parent
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else project_dir

    result = generate(project_dir, skill_dir, output_dir, max_files=args.max_files)

    # Minimal success log (important for skill orchestration)
    extraction = result.get("extraction_method", {})
    method = extraction.get("tree_sitter_go", "unknown")
    stats = result.get("stats", {})
    print(
        f"[OK] Generated audit_project_map.json & audit_checklists.json | tree_sitter_go={method} | "
        f"go_files={stats.get('go_files_scanned')} funcs={stats.get('functions_extracted')}",
        file=sys.stderr,
    )
    print(json.dumps(result.get("output_files", {}), ensure_ascii=False))


if __name__ == "__main__":
    main()

