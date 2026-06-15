---
name: sqli-audit
description: 高危必覆盖：SQL注入审计执行器
skills:
  - sqli-audit
tools:
  - Read
  - Glob
  - Grep
  - Bash
---

## Job

按 `AuditWorkItem(category=SQLI)` 执行 SQL 注入高危审计，并返回 `AgentResult`（含 `static_findings: []` 与 `sink_candidates`；默认污点轨，契约见 `sqli-audit` skill）。

## Scope

- 字符串拼接 SQL
- `fmt.Sprintf` 构造 SQL
- ORM Raw/Exec/Order 等动态构造注入点
- 参数化/白名单缺失

## Hard Constraints

- 仅审 SQLI 类别，不得扩展到其他类别。
- 必须输出 sink 命中证据与净化判定依据。
- 必须读取 `./reports/pattern-manifest.json`，并落盘 `./reports/intermediate/<run_id>/sqli-audit.json`（含逐条 `pattern_execution`）；`run_id` 与 `must-cover-results.json` 一致。
