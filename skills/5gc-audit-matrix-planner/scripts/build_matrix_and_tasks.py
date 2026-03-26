#!/usr/bin/env python3
"""
Build:
  - audit_matrix.json
  - audit_tasklist.json
  - audit_tasks/*.md

Inputs (from project root by default):
  - audit_project_map.json (from 5gc-audit-decompose-map-checklist)
  - audit_checklists.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _write_text(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _stable_sort_key(x: str) -> Tuple[int, str]:
    # keep deterministic ordering
    m = re.search(r"(\d+)$", x)
    return (int(m.group(1)) if m else 0, x)


def _module_match_score(module: Dict[str, Any], category: Dict[str, Any], check_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    module_path = (module.get("path") or "").lower()
    module_signals = [s.lower() for s in (module.get("module_signals") or [])]
    evidence: List[Dict[str, Any]] = []
    score = 0

    fn_names = set()
    for fid in module.get("function_ids", []) or []:
        # function_ids are in audit_project_map; we do not have function names here
        fn_names.add(fid)

    for ci in check_items:
        ev = ci.get("evidence", {}) or {}
        module_path_contains = [s.lower() for s in (ev.get("module_path_contains") or [])]
        file_path_contains = [s.lower() for s in (ev.get("file_path_contains") or [])]
        function_name_contains = [s.lower() for s in (ev.get("function_name_contains") or [])]
        string_regex_any = [s for s in (ev.get("string_regex_any") or [])]

        ci_hits = []

        # module-level hits
        if any(x in module_path for x in module_path_contains if x):
            score += 4
            ci_hits.append("module_path_contains")
        if any(x in module_path for x in file_path_contains if x):
            score += 3
            ci_hits.append("file_path_contains")

        # signal-level hits
        if any(sig in module_signals for sig in ["has_pfcp", "has_sbi", "has_nas", "has_ngap", "has_gtp"]):
            # tiny score bump: signals are already coarse
            score += 1

        # function_name_contains cannot be evaluated without functions list;
        # we handle it later when picking entries.

        if ci_hits:
            evidence.append({"check_id": ci.get("check_id"), "hits": ci_hits})

    coverage = "low"
    if score >= 8:
        coverage = "high"
    elif score >= 4:
        coverage = "medium"

    return {"score": score, "coverage": coverage, "evidence": evidence[:10]}


def _func_in_module(func: Dict[str, Any], module: Dict[str, Any]) -> bool:
    mod_path = (module.get("path") or "").strip()
    if not mod_path:
        return False
    fpath = (func.get("file") or "").strip()
    return fpath.startswith(mod_path + "/") or fpath == mod_path


def _text_any_contains(hay: str, needles: List[str]) -> bool:
    h = (hay or "").lower()
    return any(n.lower() in h for n in needles if n)


def _candidate_functions_for_check(
    module: Dict[str, Any],
    functions_by_id: Dict[str, Dict[str, Any]],
    entry_candidates: List[Dict[str, Any]],
    check_item: Dict[str, Any],
    category: Dict[str, Any],
    all_functions_in_module: List[Dict[str, Any]],
) -> Dict[str, Any]:
    ev = check_item.get("evidence", {}) or {}
    task_gen = check_item.get("task_generation", {}) or {}

    ev_fn_contains = [s for s in (ev.get("function_name_contains") or []) if isinstance(s, str)]
    ev_file_contains = [s for s in (ev.get("file_path_contains") or []) if isinstance(s, str)]
    key_sinks = [s for s in (task_gen.get("key_sinks") or []) if isinstance(s, str)]

    # Choose entry
    chosen_entry: Optional[Dict[str, Any]] = None
    for ec in entry_candidates:
        fid = ec.get("func_id")
        if not fid:
            continue
        fn = functions_by_id.get(fid)
        if not fn:
            continue
        if not _func_in_module(fn, module):
            continue

        ok = True
        if ev_fn_contains:
            ok = _text_any_contains(ec.get("name") or "", ev_fn_contains) or _text_any_contains(fn.get("name") or "", ev_fn_contains)
        if ok and ev_file_contains:
            ok = _text_any_contains(fn.get("file") or "", ev_file_contains)

        if ok:
            chosen_entry = ec
            break

    if chosen_entry is None:
        # fallback to any function in module
        for fn in all_functions_in_module:
            if ev_fn_contains and _text_any_contains(fn.get("name") or "", ev_fn_contains):
                chosen_entry = {
                    "func_id": fn["func_id"],
                    "kind": "fallback_entry",
                    "name": fn.get("name"),
                    "file": fn.get("file"),
                    "line": fn.get("line", 0),
                }
                break

    if chosen_entry is None:
        return {"skip": True, "reason": "no entry_candidates match"}

    # Candidate functions: entry + keys/sanitizers-like functions in module
    expected_sanitizers = list(ev.get("expected_sanitizers") or [])
    candidates: List[Dict[str, Any]] = []
    entry_fn = functions_by_id.get(chosen_entry["func_id"])
    if entry_fn:
        candidates.append(entry_fn)

    for fn in all_functions_in_module:
        nm = fn.get("name") or ""
        fp = fn.get("file") or ""
        # match key sinks / expected sanitizers / validation keywords
        if key_sinks and any(k and k.lower() in nm.lower() for k in key_sinks):
            candidates.append(fn)
        elif expected_sanitizers and any(s and s.lower() in nm.lower() for s in expected_sanitizers):
            candidates.append(fn)
        elif re.search(r"(Decode|Unmarshal|Parse|Validate|Verify|Check|Auth|Authorize|Owner|Association|Session)", nm):
            candidates.append(fn)
        elif re.search(r"(Decode|Unmarshal|Parse)", fp, re.IGNORECASE):
            candidates.append(fn)

    # de-dup by func_id
    seen = set()
    deduped = []
    for c in candidates:
        fid = c.get("func_id")
        if not fid or fid in seen:
            continue
        seen.add(fid)
        deduped.append(c)
    deduped = deduped[:6]

    primary_funcs = deduped[:2]  # entry + first sink-like
    secondary_funcs = deduped[2:]

    return {
        "skip": False,
        "entry": chosen_entry,
        "candidate_functions": deduped,
        "primary_functions": primary_funcs,
        "secondary_functions": secondary_funcs,
        "stop_conditions": task_gen.get("stop_conditions") or [],
        "key_sinks": key_sinks,
        "expected_sanitizers": ev.get("expected_sanitizers") or [],
    }


def _render_task_md(
    task: Dict[str, Any],
    template: str,
) -> str:
    # For simplicity: no complex templating engine.
    # We insert task fields into a readable markdown file.
    scope = task.get("scope")
    title = f"Task {task.get('task_id')} ({scope})"

    checks = task.get("checks") or []
    checks_md = "\n".join([f"- `{c}`" for c in checks]) if checks else "- (none)"
    stop_md = "\n".join([f"- {s}" for s in (task.get("stop_conditions") or [])]) if task.get("stop_conditions") else "- (none)"

    main_files_md = "\n".join([f"- `{x}`" for x in (task.get("primary_files") or [])]) if task.get("primary_files") else "- (unknown)"
    sec_files_md = "\n".join([f"- `{x}`" for x in (task.get("secondary_files") or [])]) if task.get("secondary_files") else "- (none)"
    main_funcs_md = "\n".join([f"- `{x}`" for x in (task.get("primary_functions") or [])]) if task.get("primary_functions") else "- (unknown)"
    sec_funcs_md = "\n".join([f"- `{x}`" for x in (task.get("secondary_functions") or [])]) if task.get("secondary_functions") else "- (none)"

    return (
        f"{template}\n\n"
        f"---\n\n"
        f"# {title}\n\n"
        f"## Target Scope\n"
        f"- `scope`: `{scope}`\n"
        f"- `module_id`: `{task.get('module_id')}`\n"
        f"- `category_id`: `{task.get('category_id')}`\n"
        + (
            f"- `business_flow_id`: `{task.get('business_flow_id')}`\n"
            if task.get("business_flow_id")
            else ""
        )
        + f"- `check_id(s)`: {', '.join(checks) if checks else '-'}\n"
        f"\n## Primary & Secondary\n"
        f"### Primary files\n{main_files_md}\n"
        f"### Secondary files\n{sec_files_md}\n"
        f"### Primary functions\n{main_funcs_md}\n"
        f"### Secondary functions\n{sec_funcs_md}\n"
        f"\n## Used Checklist\n{checks_md}\n"
        f"\n## Scan Steps\n"
        f"1. (business flow 中间粒度) 准调用链/关键节点定位：只列关键路径与关键节点，不展开到单函数完整证据链重复。\n"
        f"2. (single function 精审) 对主要/次要函数检查输入验证、净化、鉴权门控、错误处理与边界条件，并给出 source->sink 证据。\n"
        f"\n## Termination Conditions\n{stop_md}\n"
        f"\n## Outputs (placeholders)\n"
        f"- Findings: [填充占位]\n"
        f"- Uncertainties: [填充占位]\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", required=True, help="Target project directory containing audit_project_map.json")
    ap.add_argument("--task-limit", type=int, default=120, help="Max single_function tasks to generate")
    ap.add_argument("--max-modules", type=int, default=200, help="Cap modules to keep planning cheap")
    ap.add_argument("--max-business-flows-per-module", type=int, default=6)
    ap.add_argument("--max-functions-per-task", type=int, default=6)
    args = ap.parse_args()

    project_dir = Path(args.project_dir).expanduser().resolve()
    if not project_dir.exists():
        print(f"[ERROR] project_dir not found: {project_dir}", file=sys.stderr)
        sys.exit(2)

    project_map_path = project_dir / "audit_project_map.json"
    checklists_path = project_dir / "audit_checklists.json"
    if not project_map_path.exists() or not checklists_path.exists():
        print("[ERROR] Missing audit_project_map.json or audit_checklists.json. Run skill-1 first.", file=sys.stderr)
        sys.exit(2)

    project_map = _load_json(project_map_path)
    checklists = _load_json(checklists_path)

    modules = project_map.get("modules") or []
    functions = project_map.get("functions") or []
    entry_candidates = (project_map.get("entry_candidates") or {})
    entry_list = []
    entry_list.extend(entry_candidates.get("sbi_handlers", []) or [])
    entry_list.extend(entry_candidates.get("protocol_handlers", []) or [])

    functions_by_id = {f.get("func_id"): f for f in functions if f.get("func_id")}

    # index module -> funcs
    for m in modules:
        m["function_ids"] = m.get("function_ids") or []

    # Load template
    skill_dir = Path(__file__).resolve().parent.parent
    template_path = skill_dir / "references" / "audit_task_md_template.md"
    template = template_path.read_text(encoding="utf-8") if template_path.exists() else "# audit_tasks template"

    out_dir = project_dir / "audit_tasks"
    out_dir.mkdir(parents=True, exist_ok=True)

    audit_matrix: Dict[str, Any] = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rows": [],
        "columns": [],
        "cells": {},
    }

    audit_tasklist: Dict[str, Any] = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "module_taskgroups": [],
    }

    categories = checklists.get("checklist_categories") or []
    audit_matrix["columns"] = [c.get("category_id") for c in categories]

    # Pre-compute modules cap
    modules_sorted = modules[:]
    modules_sorted = modules_sorted[: args.max_modules]

    single_task_count = 0

    for mi, module in enumerate(modules_sorted):
        module_id = module.get("module_id")
        if not module_id:
            continue
        audit_matrix["rows"].append(module_id)
        audit_matrix["cells"][module_id] = {}

        # Prepare module functions list
        funcs_in_module: List[Dict[str, Any]] = []
        for fid in module.get("function_ids") or []:
            fn = functions_by_id.get(fid)
            if fn:
                funcs_in_module.append(fn)

        all_functions_in_module = funcs_in_module[:400]

        # Compute category relevance (module signals + evidence)
        category_scores: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
        for cat in categories:
            cat_id = cat.get("category_id")
            check_items = cat.get("check_items") or []
            if not cat_id or not isinstance(check_items, list):
                continue
            score_obj = _module_match_score(module, cat, check_items)
            audit_matrix["cells"][module_id][cat_id] = score_obj
            category_scores.append((cat_id, score_obj, cat))

        # Sort by score desc
        category_scores.sort(key=lambda x: (x[1].get("score", 0), x[0]), reverse=True)
        # Only keep top categories
        selected_categories = [cs for cs in category_scores if cs[1].get("score", 0) > 0][:5]

        module_group = {
            "module_id": module_id,
            "module_path": module.get("path"),
            "business_flows": [],
        }

        business_flow_count = 0
        for cat_id, score_obj, cat in selected_categories:
            if business_flow_count >= args.max_business_flows_per_module:
                break
            check_items = cat.get("check_items") or []
            # For each check_item create at most one business flow
            for ci in check_items[:3]:
                if business_flow_count >= args.max_business_flows_per_module:
                    break
                category_id = cat_id
                check_id = ci.get("check_id")
                if not check_id:
                    continue

                plan = _candidate_functions_for_check(
                    module=module,
                    functions_by_id=functions_by_id,
                    entry_candidates=entry_list,
                    check_item=ci,
                    category=cat,
                    all_functions_in_module=all_functions_in_module,
                )
                if plan.get("skip"):
                    continue

                business_flow_id = f"BF-{mi:02d}-{category_id}-{check_id}".replace("/", "_")
                entry = plan.get("entry") or {}
                candidate_functions = plan.get("candidate_functions") or []
                primary_functions = plan.get("primary_functions") or []
                secondary_functions = plan.get("secondary_functions") or []

                business_flow_obj = {
                    "business_flow_id": business_flow_id,
                    "category_id": category_id,
                    "check_id": check_id,
                    "entry_func_id": entry.get("func_id"),
                    "entry_name": entry.get("name"),
                    "entry_file": entry.get("file"),
                    "entry_line": entry.get("line"),
                    "candidate_functions": [f.get("func_id") for f in candidate_functions if f.get("func_id")],
                    "stop_conditions": plan.get("stop_conditions") or [],
                }
                module_group["business_flows"].append(business_flow_obj)

                # Generate task md for business flow
                task_id = f"TASK-{mi:03d}-{len(module_group['business_flows']):04d}"
                task_md = _render_task_md(
                    {
                        "task_id": task_id,
                        "scope": "business_flow",
                        "module_id": module_id,
                        "category_id": category_id,
                        "business_flow_id": business_flow_id,
                        "checks": [check_id],
                        "primary_files": [f"{entry.get('file')}:{entry.get('line', 0)}"],
                        "secondary_files": [],
                        "primary_functions": [f"{f.get('name')}@{f.get('file')}:{f.get('line')}" for f in primary_functions if f.get("name")],
                        "secondary_functions": [f"{f.get('name')}@{f.get('file')}:{f.get('line')}" for f in secondary_functions if f.get("name")],
                        "stop_conditions": plan.get("stop_conditions") or [],
                    },
                    template=template,
                )
                _write_text(out_dir / f"{module_id}-{business_flow_id}-business.md", task_md)

                # Generate single function tasks (limit)
                for fn in candidate_functions:
                    if single_task_count >= args.task_limit:
                        break
                    single_task_id = f"{task_id}-SF"
                    main_fn = fn
                    main_files = [f"{main_fn.get('file')}:{main_fn.get('line', 0)}"]
                    # choose a couple secondary funcs (first in list excluding itself)
                    sec = [x for x in (candidate_functions or []) if x.get("func_id") != main_fn.get("func_id")][:2]
                    sec_funcs_md = [f"{x.get('name')}@{x.get('file')}:{x.get('line')}" for x in sec if x.get("name")]
                    sec_files_md = [f"{x.get('file')}:{x.get('line', 0)}" for x in sec if x.get("file")]

                    single_task_md = _render_task_md(
                        {
                            "task_id": single_task_id,
                            "scope": "single_function",
                            "module_id": module_id,
                            "category_id": category_id,
                            "business_flow_id": business_flow_id,
                            "checks": [check_id],
                            "primary_files": main_files,
                            "secondary_files": sec_files_md,
                            "primary_functions": [f"{main_fn.get('name')}@{main_fn.get('file')}:{main_fn.get('line')}"],
                            "secondary_functions": sec_funcs_md,
                            "stop_conditions": plan.get("stop_conditions") or [],
                        },
                        template=template,
                    )
                    _write_text(out_dir / f"{module_id}-{business_flow_id}-{main_fn.get('func_id')}-single.md", single_task_md)
                    single_task_count += 1

                business_flow_count += 1

        audit_tasklist["module_taskgroups"].append(module_group)

    # Save outputs
    (project_dir / "audit_matrix.json").write_text(json.dumps(audit_matrix, indent=2, ensure_ascii=False), encoding="utf-8")
    (project_dir / "audit_tasklist.json").write_text(json.dumps(audit_tasklist, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        f"[OK] Generated audit_matrix.json, audit_tasklist.json and audit_tasks/* | modules={len(modules_sorted)} single_tasks={single_task_count}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()

