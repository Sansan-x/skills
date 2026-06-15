# Pattern coverage traceability — JSON contracts (`schema_version` 1.2)

本文档定义 `./reports/pattern-manifest.json`、各 agent **中间结果** JSON，以及 `./reports/must-cover-results.json` 中与攻击模式覆盖追溯相关的字段。编排层 `schema_version` 自 **1.2** 起包含下列键（与 1.1 向后兼容：新增键不得破坏既有必填键）。

---

## 1. `./reports/pattern-manifest.json`

| 字段 | 类型 | 说明 |
|------|------|------|
| `schema_version` | string | 固定 `"1.0"`（manifest 自有版本，独立于 must-cover-results） |
| `generated_at` | string | ISO-8601 UTC |
| `producer` | string | 固定 `"project-analyzer"`（或由 orchestrator 补齐时标注 `"orchestrator-backfill"`） |
| `run_alignment` | string | 可选；与本轮 `must-cover-results.generated_at` 或策略哈希对齐的说明 |
| `patterns` | array | 模式条目列表 |

**`patterns[]` 每条：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `pattern_id` | string | 是 | 全局唯一，建议 `{CATEGORY}_{SLUG}_{序号}`，如 `FILE_OPS_PATH_TRAVERSAL_001` |
| `category` | string | 是 | `FILE_OPS` \| `SQLI` \| `GO_RUNTIME` \| `GO_AUDIT_DETECTOR` |
| `source_ref` | string | 是 | references 路径 + 章节，如 `skills/file-audit/references/file-ops-vulnerability-patterns.md##路径穿越` |
| `required_level` | string | 是 | `must` \| `conditional` \| `optional` |
| `applicability_hint` | string | 否 | 供 agent 判断是否 `NOT_APPLICABLE_BY_STACK` |

---

## 2. 中间结果：`./reports/intermediate/<run_id>/<artifact>.json`

`run_id` 必须与写入 `must-cover-results.json` 的 `run_id` 一致（建议使用 `YYYYMMDD-HHMM` 或 UUID，与编排约定一致）。

| 文件名 | 产出方 |
|--------|--------|
| `file-audit.json` | `file-audit` agent |
| `sqli-audit.json` | `sqli-audit` agent |
| `go-runtime-audit-core.json` | `go-runtime-audit` skill（GO_RUNTIME 串行第一段） |
| `go-unique-patterns-extra.json` | `go-unique-patterns-extra` skill（GO_RUNTIME 串行第二段） |
| `go-audit-detector.json` | `go-audit-detector` agent |

**中间 JSON 顶层（共通）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `schema_version` | string | `"1.0"` |
| `run_id` | string | 与目录名一致 |
| `agent` | string | 逻辑 agent：`file-audit` \| `sqli-audit` \| `go-runtime-audit` \| `go-unique-patterns-extra` \| `go-audit-detector` |
| `category_id` | string | `FILE_OPS` \| `SQLI` \| `GO_RUNTIME` \| `GO_AUDIT_DETECTOR` |
| `generated_at` | string | ISO-8601 UTC |
| `pattern_manifest_ref` | string | 固定 `./reports/pattern-manifest.json` |
| `files_scanned` | array of string | 与 `AgentResult.files_scanned` 对齐 |
| `patterns_loaded` | array of string | `pattern_id` 列表，**须为 manifest 中本 category 的子集** |
| `patterns_executed` | array of string | 实际执行审查的 `pattern_id`（`patterns_executed ⊆ patterns_loaded`） |
| `pattern_execution` | array | 见下表 |
| `sink_candidates` | array | 可选镜像；权威聚合仍以 orchestrator 合并为准 |
| `static_findings` | array | 可选镜像 |
| `findings` | array | 可选 |
| `no_finding_evidence` | string | 无命中时必填（与 skill 契约一致） |
| `errors` | array | 可选 |

**`pattern_execution[]` 每条：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `pattern_id` | string | 是 | |
| `status` | string | 是 | `executed_hit` \| `executed_no_hit` \| `skipped` \| `blocked` |
| `files_scanned` | array | 否 | 该模式审查涉及的文件子集 |
| `evidence_refs` | array of string | 否 | 如 `finding:ID`、`sink:ID`、`static:ID` |
| `no_finding_evidence` | string | 条件 | `executed_no_hit` 时建议填写检索/语义核对摘要 |
| `skip_reason_code` | string | 条件 | `skipped` 或 `blocked` 时**必填** |
| `skip_reason_detail` | string | 否 | 人类可读补充 |

**`skip_reason_code` 枚举：**

- `NOT_APPLICABLE_BY_STACK` — 代码栈/依赖不存在该攻击面（须可复核）
- `OUT_OF_SCOPE_BY_STRATEGY` — 策略排除或未纳入 must 范围
- `BUDGET_EXHAUSTED`
- `PARSER_LIMITATION`
- `DEPENDENCY_MISSING`
- `UNKNOWN` — 仅当无法归类；应尽量避免

**Gate-P 允许对 `required_level=must` 的 `skipped`：** 仅当 `skip_reason_code` 为 `NOT_APPLICABLE_BY_STACK` 或 `OUT_OF_SCOPE_BY_STRATEGY`，且 `skip_reason_detail` 非空。

---

## 3. `./reports/must-cover-results.json`（`schema_version` **1.2** 扩展）

在 1.1 必填键之外增加：

| 字段 | 类型 | 说明 |
|------|------|------|
| `schema_version` | string | **`"1.2"`** |
| `run_id` | string | 与 `./reports/intermediate/<run_id>/` 一致 |
| `pattern_manifest_ref` | string | 固定 `./reports/pattern-manifest.json` |
| `intermediate_dir` | string | 如 `./reports/intermediate/<run_id>/` |
| `pattern_coverage_matrix` | object | 键为 `pattern_id`，值为合并后的单条摘要（见下） |
| `pattern_coverage_metrics` | object | 聚合计数，供附录 A.3 与闸门 |

**`pattern_coverage_matrix[pattern_id]`：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `category` | string | 来自 manifest |
| `required_level` | string | 来自 manifest |
| `final_status` | string | 跨 agent 合并：`executed_hit` \| `executed_no_hit` \| `skipped` \| `blocked` \| `missing` |
| `contributing_agents` | array | 如 `[{"agent":"file-audit","status":"executed_no_hit"}]` |
| `skip_reason_code` | string | 若最终为 `skipped`/`blocked`/`missing` |
| `skip_reason_detail` | string | 可选 |
| `evidence_refs` | array | 合并去重 |

**`pattern_coverage_metrics` 建议字段：**

- `must_total`, `must_executed_hit`, `must_executed_no_hit`, `must_skipped_ok`, `must_failed_or_missing`
- `patterns_with_skip_reason_count`
- `intermediate_files_expected`, `intermediate_files_present`

**`gate_status` 扩展：**

- `Gate-P`：`pass` \| `fail` — 全部 `required_level=must` 的模式不得为 `missing`；不得为 `skipped`/`blocked` 除非 `skip_reason_code` 属于允许集合。

---

## 4. Orchestrator 行为摘要

1. 启动时读取 `./reports/pattern-manifest.json`；若缺失或非空校验失败：**中止**并提示先运行 `project-analyzer` 重新生成策略与 manifest（本仓库**写死**此路径，不采用静默空 manifest）。
2. 收集 `./reports/intermediate/<run_id>/*.json`，合并 `GO_RUNTIME` 两段（`go-runtime-audit-core` + `go-unique-patterns-extra`）为逻辑视图；冲突写入 `pattern_coverage_matrix` 的 `errors` 或顶层 `pattern_coverage_errors` 并使 `Gate-P` fail。
3. 将 `pattern_coverage_matrix` 与 `pattern_coverage_metrics` 写入 `must-cover-results.json`。

---

## 5. Judge 消费说明

`go-audit-judge` 仍主要读取 `./reports/must-cover-results.json` 与 `./reports/trace-results.json`。编排输出 **`schema_version` 为 `1.2`** 时，Judge 必须校验顶层存在 `run_id`、`pattern_coverage_matrix`、`pattern_coverage_metrics`、`gate_status.Gate-P`；从 `pattern_coverage_matrix` / `pattern_coverage_metrics` 填写附录 **A.3** 的逐模式摘要表；**不必**强制单独打开 `pattern-manifest.json`（manifest 为编排与生成侧真相源）。
