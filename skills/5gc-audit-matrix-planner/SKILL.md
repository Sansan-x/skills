---
name: 5gc-audit-matrix-planner
description: 把 `audit_project_map.json`（模块/函数/入口候选）与 `audit_checklists.json`（检查项体系）组合成 `audit_matrix.json` 和 `audit_tasklist.json`，并生成可执行的 `audit_tasks/*.md` 任务清单，用于后续 business flow -> 单函数 推理式代码审计。只要用户要“在地图/检查清单基础上规划审计任务/产出 task md / matrix”，就必须使用本 skill。
---

# 5GC Matrix Planner (module x checklist -> tasks)

## 触发条件
- 用户已经有 `audit_project_map.json` 和 `audit_checklists.json`（或明确让你基于它们继续）
- 用户要求“生成 matrix / tasklist / audit_tasks md（用于审计规划）”
- 用户要求“按 module -> business flow -> 单函数 的粒度规划任务”（business flow 用于准调用链/关键节点定位）

## 执行方式（由你在执行时调用脚本）
在 `workspace root = 目标项目目录` 下运行：
```bash
python scripts/build_matrix_and_tasks.py --project-dir <project_dir>
```

## 必要产物（在目标项目根目录）
- `audit_matrix.json`
- `audit_tasklist.json`
- `audit_tasks/` 目录（内含若干 `*.md`）

## 输出内容约束（便于 executor 消费）
- `audit_matrix.json`：
  - `rows`: module（module_id）
  - `columns`: checklist 类别（category_id）
  - `cells`: 每个 module 对应类别的高风险/覆盖证据（数组，允许为空）
- `audit_tasklist.json`：
  - 按 module 分组
  - 每个 module 下包含若干 `business_flows[]`
  - 每个 business flow 下包含 `candidate_functions[]`
- `audit_tasks/*.md`：
  - 必须写清楚 `scope`（module / business_flow / single_function）
  - 必须写清楚“扫描方法”和“终止信号”（stop_conditions）
  - business flow 阶段必须只做准调用链/关键节点定位，不重复单函数完整证据链

