---
name: 5gc-audit-executor
description: 执行基于 5GC 审计规划产物（`audit_tasks/*.md` / `audit_tasklist.json` / `audit_matrix.json`）的“模块->业务流(中间粒度)->单函数”代码审计推理，并输出最终中文安全审计报告（报告结构对齐 `skills/go-audit/references/report-template.md`）。当用户已经生成了任务规划/任务 md，并要求“开始审计、输出报告、完成 reasoning”时使用本 skill。
---

# 5GC Audit Executor (module -> business flow -> single function)

## 触发条件
- 项目目录下已存在 `audit_tasks/`（或至少存在 `audit_tasklist.json`）
- 用户要求“开始推理审计并输出报告”

## 必要输入（从 workspace root 读取）
- `audit_project_map.json`（可选但建议，用于项目概况）
- `audit_tasklist.json`
- `audit_tasks/*.md`

## 执行方式（建议脚本先跑）
在 `workspace root = 目标项目目录` 下执行：
```bash
python scripts/order_tasks_and_skeleton.py --project-dir <project_dir>
```

脚本将生成：
- `ordered_tasks.json`（用于严格排序：module -> business flow -> single function）
- `./reports/<name>-5gcoreaudit-<timestamp>.md`（报告骨架，供你填充）

## 推理与输出规则（严格执行顺序）
1. `module` 粒度
   - 只负责给出模块级风险摘要与“本模块将要扫哪些 checklist 类别/为什么”
   - 不做 single function 级别的完整证据链重复

2. `business flow` 粒度（中间粒度）
   - 只做“准调用链/关键节点”定位：入口消息/数据从哪里来、在关键节点上发生了哪些校验/净化/鉴权/状态变更
   - 输出业务流阶段的结论（证据充分/证据不足/疑似），不展开到每个函数的 full chain

3. `single function` 粒度（细粒度）
   - 针对 task md 指定的主要函数与次要函数做精审
   - 对应 checklist 的 `check_id`，逐项核对：关键验证是否存在、是否被绕过、source->sink 路径是否成立
   - 必须避免臆想：当关键上下文无法从代码中确认时，标记为“待补充证据”，不要编造行号/代码片段

## 报告输出
- 输出到 `./reports/` 目录下
- 文件命名：`[项目名称]-5gcoreaudit-[YYYYMMDD-HHMM].md`
- 报告内容结构尽量复用 `skills/go-audit/references/report-template.md` 的章节顺序

## 终止条件
- 当所有 `ordered_tasks.json` 中的任务（至少所有 business_flow 与被规划的 single_function）都完成推理后，停止并输出最终报告

