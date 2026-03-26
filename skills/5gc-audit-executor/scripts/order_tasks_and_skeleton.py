#!/usr/bin/env python3
"""
Expand audit_tasklist.json into ordered tasks:
  module -> business flow -> single function

Then write:
  - ordered_tasks.json
  - report skeleton markdown in ./reports/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _project_name(project_dir: Path) -> str:
    # prefer directory name (safe)
    return re.sub(r"[^A-Za-z0-9_-]+", "-", project_dir.name).strip("-") or "project"


def _find_one_task_md(audit_tasks_dir: Path, pattern: str) -> Optional[str]:
    # pattern is a glob suffix, like "{module}-{bf}-{func}-single.md"
    matches = sorted([str(p) for p in audit_tasks_dir.glob(pattern)])
    return matches[0] if matches else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", required=True, help="Target project directory containing audit_tasklist.json")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).expanduser().resolve()
    audit_tasklist_path = project_dir / "audit_tasklist.json"
    audit_project_map_path = project_dir / "audit_project_map.json"
    audit_tasks_dir = project_dir / "audit_tasks"

    if not audit_tasklist_path.exists():
        print(f"[ERROR] Missing audit_tasklist.json: {audit_tasklist_path}", file=sys.stderr)
        sys.exit(2)
    if not audit_tasks_dir.exists():
        print(f"[ERROR] Missing audit_tasks/ directory: {audit_tasks_dir}", file=sys.stderr)
        sys.exit(2)

    project_map = _read_json(audit_project_map_path) if audit_project_map_path.exists() else {}
    tasklist = _read_json(audit_tasklist_path)

    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d-%H%M")

    reports_dir = project_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    name = _project_name(project_dir)
    report_path = reports_dir / f"{name}-5gcoreaudit-{ts}.md"

    ordered_tasks: List[Dict[str, Any]] = []
    module_groups = tasklist.get("module_taskgroups") or []
    for mg in module_groups:
        module_id = mg.get("module_id")
        module_path = mg.get("module_path")
        business_flows = mg.get("business_flows") or []
        for bf in business_flows:
            bf_id = bf.get("business_flow_id")
            category_id = bf.get("category_id")
            check_id = bf.get("check_id")

            business_md = _find_one_task_md(
                audit_tasks_dir,
                f"{module_id}-{bf_id}-business.md".replace("**", "*"),
            )
            # The planner uses exact file naming: <module_id>-<business_flow_id>-business.md
            # If not found, attempt a relaxed glob.
            if not business_md:
                business_md = _find_one_task_md(audit_tasks_dir, f"{module_id}-{bf_id}*-business.md")

            ordered_block = {
                "scope_order": "module->business_flow->single_function",
                "module_id": module_id,
                "module_path": module_path,
                "business_flow_id": bf_id,
                "category_id": category_id,
                "check_id": check_id,
                "business_task_md": business_md,
                "entry_func_id": bf.get("entry_func_id"),
                "entry_name": bf.get("entry_name"),
                "candidate_functions": bf.get("candidate_functions") or [],
                "single_function_task_mds": [],
            }

            for func_id in ordered_block["candidate_functions"]:
                sf_md = _find_one_task_md(
                    audit_tasks_dir,
                    f"{module_id}-{bf_id}-{func_id}-single.md".replace("**", "*"),
                )
                if not sf_md:
                    sf_md = _find_one_task_md(audit_tasks_dir, f"{module_id}-{bf_id}-{func_id}*-single.md")
                if sf_md:
                    ordered_block["single_function_task_mds"].append({"func_id": func_id, "task_md": sf_md})
            ordered_tasks.append(ordered_block)

    ordered_path = project_dir / "ordered_tasks.json"
    ordered_path.write_text(json.dumps({"generated_at": now.isoformat(), "ordered_tasks": ordered_tasks}, indent=2, ensure_ascii=False), encoding="utf-8")

    # Report skeleton. Keep it simple but with go-audit template chapter order.
    exec_date = now.strftime("%Y-%m-%d")
    nf_type = (project_map.get("project_context") or {}).get("nf_type") if isinstance(project_map.get("project_context"), dict) else None
    # project_map from skill-1 stores only raw module info, not project_context. Keep generic.
    nf_line = f"5GC NF: {nf_type}" if nf_type else "5GC NF: [待从 audit_project_map.json 补充]"

    skeleton = f"""# Go代码安全审计报告：[项目名称] {name}

**审计日期：** {exec_date}
**审计执行：** Claude（AI辅助代码审计）
**审计模式：** module -> business flow -> single function
**审计领域：** 云核领域
**报告版本：** 1.0

---
## 1. 执行摘要
- 总体风险评估：待填充
- 本次审计任务总数：待填充
- 关键发现：待填充
- 攻击链识别：待填充
- 首要修复建议：待填充

---
## 2. 项目概况
- {nf_line}
- 技术栈/入口协议：待填充（可从 `audit_project_map.json` 的 entry_candidates 与 module_signals 推断）
- 架构概述与信任边界：待填充

---
## 3. 审计范围与方法
- 范围：待填充（以 `audit_tasks/` 实际存在的文件为准）
- 方法论：
  - 先 module 总览
  - 再 business flow 准调用链/关键节点定位
  - 最后 single function 精审并按 checklist 逐项核对

---
## 4. 发现汇总
| ID | 标题 | 严重性 | CWE | 位置 | 置信度 |
|----|------|--------|-----|------|--------|
| VULN-001 | [填充] | [填充] | [填充] | [填充] | [填充] |

---
## 5. 详细发现
（按 `ordered_tasks.json` 的顺序逐步填充。若暂未确认漏洞，请在此章节写明“未确认”，并列出“疑似点/待补充证据”。）

---
## 6. 攻击链分析
待填充

---
## 7. 修复优先级矩阵
待填充

---
## 8. 附录
- A. 完整文件列表：待填充
- B. 排除的误报：待填充
- C. 方法论说明：待填充（包含 checklist 类别、任务生成来源）
"""

    report_path.write_text(skeleton, encoding="utf-8")

    # Print paths for skill orchestration
    print(f"[OK] ordered_tasks.json: {ordered_path}", file=sys.stderr)
    print(f"[OK] report skeleton: {report_path}", file=sys.stderr)
    print(json.dumps({"ordered_tasks_json": str(ordered_path), "report_path": str(report_path)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

