---
name: orchestrator-audit
description: 读取审计策略并并行调度 must-cover agent，执行 gate 判定与定向 backfill。
---

# Orchestrator Audit

用于连接 `project-analyzer`、detector 层与 judge 层，将策略转化为可执行的并行审计任务并输出统一聚合结果。

## 输入约束

必须读取：

- `./reports/audit-strategy-plan.md`
- `./reports/pattern-manifest.json`

若 `audit-strategy-plan.md` 不存在或为空：中止并提示先运行 `project-analyzer`。

若 `pattern-manifest.json` 不存在、不可解析或 `patterns` 为空数组：中止并提示先运行 `project-analyzer` 生成模式清单（与策略同次写入 `./reports/`）。**不得**使用空 manifest 继续编排。

**`run_id`（本轮编排标识）**：在生成 `AuditWorkItem` 前确定（建议 UTC `YYYYMMDD-HHMM` 或 UUID），写入即将落盘的 `./reports/must-cover-results.json` 顶层 `run_id`，并作为 `./reports/intermediate/<run_id>/` 目录名；下发给各 must-cover agent / detector，使其中间 JSON 路径一致。

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
3. 生成 `AuditWorkItem`（每个 `AuditWorkItem` 须携带与本轮一致的 `run_id`）：
   - 向 `file-audit` 下发 `FILE_OPS`
   - 向 `sqli-audit` 下发 `SQLI`
   - 向 `go-runtime-audit` 下发 `GO_RUNTIME`（agent 内部串行执行 `go-runtime-audit` -> `go-unique-patterns-extra`）
4. 收集 `AgentResult` 并执行 Gate 判定：
   - Gate-1 策略完整性
   - Gate-2 必审覆盖率
   - Gate-3 必覆盖类别执行证据
   - Gate-4 加载执行一致性
   - Gate-5 Judge 输入完整性：`detector_findings` + `trace_results` + `trace_metrics` + **顶层 `static_findings`**（键必须存在；允许为空数组 `[]`，须含去重后条数 `static_findings_dedup_count` 或与 `deduped_findings` 并列的聚合说明）
   - 对 `GO_AUDIT_DETECTOR` 额外做证据完整性检查：`patterns_loaded/patterns_executed` 不得缺失（仅执行证据约束，不纳入 must-cover 三高危阻断语义）
   - **Gate-P（模式覆盖）**：在读取 `./reports/intermediate/<run_id>/` 下各中间 JSON 后判定（契约见 [pattern-coverage-json-schema.md](./references/pattern-coverage-json-schema.md)）：
     - 期望文件：`file-audit.json`、`sqli-audit.json`、`go-runtime-audit-core.json`、`go-unique-patterns-extra.json`、`go-audit-detector.json`（均须存在且可解析）。
     - 将各文件中的 `pattern_execution` 与 `pattern-manifest.json` 的 `patterns` 对齐：每个 `pattern_id` 须在矩阵中有**唯一**最终状态；`GO_RUNTIME` 条目应按 manifest 的 `source_ref` 仅由对应一段 skill 报告；若同一 `pattern_id` 出现在两段且结论冲突 → **Gate-P fail**。
     - 对 `required_level == must`：最终状态须为 `executed_hit` 或 `executed_no_hit`；或为 `skipped`/`blocked` 且 `skip_reason_code ∈ {NOT_APPLICABLE_BY_STACK, OUT_OF_SCOPE_BY_STRATEGY}` 且 `skip_reason_detail` 非空。
     - 任一 `must` 模式缺失（矩阵中无该 `pattern_id`）或状态为 `missing` → **Gate-P fail**。
5. 聚合 `sink_candidates` 与 **`static_findings`** 并执行父层 `trace-resolver`：
   - 合并 `sink_candidates` 来源：`file-audit` / `sqli-audit` / `go-runtime-audit` / `go-audit-detector`
   - 合并各 agent 与 detector 的 `static_findings`，按 `id` 去重，写入 `must-cover-results.json` 顶层键 `static_findings`，并写入 `static_findings_dedup_count`（去重后条数）
   - 父层 `trace-resolver` **仅**对污点轨候选（`evidence_model` 缺省或 `taint_traceable`）统一调用 CodeBadger MCP 获取 `trace_results`
   - 记录 `trace_metrics`（success/empty/timeout/downgrade；静态跳过计数见 `trace-results.json`）
6. Gate 失败时执行 backfill：
   - 仅重跑缺口类别 + 缺口目录
   - **Gate-P fail**：按 `pattern_coverage_metrics` / `backfill_recommendations` 定向重跑缺失中间 JSON 的 agent 或缺条目的 `category`+路径范围；保留已有效的中间 JSON，不得无条件全量重跑
7. 强制落盘 `must-cover-results`：
   - 执行 `mkdir -p ./reports` 与 `mkdir -p "./reports/intermediate/<run_id>"`（若需占位）；编排负责汇总中间 JSON
   - 写入 `./reports/must-cover-results.json`
   - 文件至少包含：`schema_version`（**`1.2`**）、`run_id`、`pattern_manifest_ref`、`intermediate_dir`、`gate_status`（含 **Gate-P**）、`file_coverage_metrics`、`pattern_execution_metrics`、`pattern_coverage_matrix`、`pattern_coverage_metrics`、`category_status`、`static_findings`、`static_findings_dedup_count`、`backfill_recommendations`
8. 输出聚合结果供 `go-audit-judge` 使用。

## 输出契约

输出 `AggregateResult`（JSON）：

```json
{
  "schema_version": "1.2",
  "run_id": "20260425-1200",
  "generated_at": "2026-04-10T00:00:00Z",
  "producer": "orchestrator",
  "pattern_manifest_ref": "./reports/pattern-manifest.json",
  "intermediate_dir": "./reports/intermediate/20260425-1200/",
  "deduped_findings": [],
  "static_findings": [],
  "static_findings_dedup_count": 0,
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
  "pattern_coverage_matrix": {},
  "pattern_coverage_metrics": {
    "must_total": 0,
    "must_executed_hit": 0,
    "must_executed_no_hit": 0,
    "must_skipped_ok": 0,
    "must_failed_or_missing": 0,
    "intermediate_files_expected": 5,
    "intermediate_files_present": 0
  },
  "gate_status": {
    "Gate-1": "pass|fail",
    "Gate-2": "pass|fail",
    "Gate-3": "pass|fail",
    "Gate-4": "pass|fail",
    "Gate-5": "pass|fail",
    "Gate-P": "pass|fail"
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
- 必须由父层统一调用 MCP（**仅**污点轨 `sink_candidates`）；不得要求 detector 子 agent 直接调用 MCP。
- `./reports/must-cover-results.json` 的 `schema_version` 须为 **`1.2`**，且顶层 **`static_findings`**、**`static_findings_dedup_count`**、**`run_id`**、**`pattern_manifest_ref`**、**`intermediate_dir`**、**`pattern_coverage_matrix`**、**`pattern_coverage_metrics`** 与 **`gate_status.Gate-P`** 不得缺失；`pattern_coverage_matrix` 的键集合须与 `pattern-manifest.json` 中 `pattern_id` 全集一致（一一对应，不得缺失）。
- `GO_AUDIT_DETECTOR` 必须有执行证据（至少 `patterns_loaded/patterns_executed`）；若缺失须在输出中标注 `evidence_missing` 并触发定向补齐，不得静默通过。
- 必须生成 `./reports/must-cover-results.json` 且非空；写入失败或缺关键字段时，本轮编排标记 `failed`。

## 参考文件

- [回归基线与判定规则](./references/regression-harness.md) — must-cover 三类召回率守护与失败处理流程。
- [模式覆盖 JSON 契约](./references/pattern-coverage-json-schema.md) — `pattern-manifest`、中间 JSON、`must-cover-results` 1.2 字段与 Gate-P 规则。
