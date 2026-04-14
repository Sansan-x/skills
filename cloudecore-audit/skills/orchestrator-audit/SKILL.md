---
name: orchestrator-audit
description: 读取审计策略并并行调度 must-cover agent，执行 gate 判定与定向 backfill。
---

# Orchestrator Audit

用于连接 `project-analyzer`、detector 层与 judge 层，将策略转化为可执行的并行审计任务并输出统一聚合结果。

## 输入约束

必须读取：

- `./reports/audit-strategy-plan.md`

若不存在或为空：中止并提示先运行 `project-analyzer`。

## 执行步骤

1. 解析策略字段：
   - `审计覆盖粒度`（必审文件、必审目录、其余范围、排除项）
   - `must_cover_categories`
   - `full_audit_categories`
   - `category_to_agent_map`
   - `coverage_gates`
   - `backfill_policy`
2. 展开统一文件清单：
   - 枚举必审目录下全部 `.go`
   - 展开必审文件 glob
   - 应用排除项过滤
3. 生成 `AuditWorkItem`：
   - 向 `file-audit` 下发 `FILE_OPS`
   - 向 `sqli-audit` 下发 `SQLI`
   - 向 `go-runtime-audit` 下发 `GO_RUNTIME`
4. 收集 `AgentResult` 并执行 Gate 判定：
   - Gate-1 策略完整性
   - Gate-2 必审覆盖率
   - Gate-3 必覆盖类别执行证据
   - Gate-4 加载执行一致性
   - Gate-5 Judge输入完整性（`detector_findings` + `trace_results` + `trace_metrics`）
   - 对 `GO_AUDIT_DETECTOR` 额外做证据完整性检查：`patterns_loaded/patterns_executed` 不得缺失（仅执行证据约束，不纳入 must-cover 三高危阻断语义）
5. 聚合 `sink_candidates` 并执行父层 `trace-resolver`：
   - 合并来源：`file-audit` / `sqli-audit` / `go-runtime-audit` / `go-audit-detector`
   - 统一调用 CodeBadger MCP 获取 `trace_results`
   - 记录 `trace_metrics`（success/empty/timeout/downgrade）
6. Gate 失败时执行 backfill：
   - 仅重跑缺口类别 + 缺口目录
7. 强制落盘 `must-cover-results`：
   - 执行 `mkdir -p ./reports`
   - 写入 `./reports/must-cover-results.json`
   - 文件至少包含：`gate_status`、`file_coverage_metrics`、`pattern_execution_metrics`、`category_status`、`backfill_recommendations`
8. 输出聚合结果供 `go-audit-judge` 使用。

## 输出契约

输出 `AggregateResult`（JSON）：

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-10T00:00:00Z",
  "producer": "orchestrator",
  "deduped_findings": [],
  "file_coverage_metrics": {
    "files_audited_unique": 0,
    "files_in_must_audit_dirs": 0,
    "files_must_audit_globs_resolved": 0,
    "must_audit_dir_coverage": 0
  },
  "pattern_execution_metrics": {
    "FILE_OPS": {"patterns_loaded": 0, "patterns_executed": 0, "sink_hits": 0},
    "SQLI": {"patterns_loaded": 0, "patterns_executed": 0, "sink_hits": 0},
    "GO_RUNTIME": {"patterns_loaded": 0, "patterns_executed": 0, "sink_hits": 0},
    "GO_AUDIT_DETECTOR": {"patterns_loaded": 0, "patterns_executed": 0, "files_scanned": 0, "sink_hits": 0, "findings": 0, "unexecuted_reason": "不确定"}
  },
  "category_status": {
    "FILE_OPS": "covered|backfilled|uncovered",
    "SQLI": "covered|backfilled|uncovered",
    "GO_RUNTIME": "covered|backfilled|uncovered",
    "GO_AUDIT_DETECTOR": "covered|backfilled|uncovered|evidence_missing"
  },
  "gate_status": {
    "Gate-1": "pass|fail",
    "Gate-2": "pass|fail",
    "Gate-3": "pass|fail",
    "Gate-4": "pass|fail",
    "Gate-5": "pass|fail"
  },
  "trace_results": [],
  "trace_metrics": {
    "trace_call_success_rate": 0,
    "trace_call_empty_rate": 0,
    "trace_call_timeout_rate": 0,
    "trace_downgrade_rate": 0,
    "judge_input_completeness": 0
  },
  "judge_inputs": {
    "detector_findings": [],
    "trace_results_ref": "inlined"
  },
  "backfill_recommendations": []
}
```

## 硬性约束

- 不得输出最终审计报告。
- 不得缩小策略定义的覆盖义务。
- 不得将“审查顺序”误当作唯一文件集合。
- 必须由父层统一调用 MCP；不得要求 detector 子 agent 直接调用 MCP。
- `GO_AUDIT_DETECTOR` 必须有执行证据（至少 `patterns_loaded/patterns_executed`）；若缺失须在输出中标注 `evidence_missing` 并触发定向补齐，不得静默通过。
- 必须生成 `./reports/must-cover-results.json` 且非空；写入失败或缺关键字段时，本轮编排标记 `failed`。

## 参考文件

- [回归基线与判定规则](./references/regression-harness.md) — must-cover 三类召回率守护与失败处理流程。
