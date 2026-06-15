---
name: sqli-audit
description: 高危必覆盖 SQLI 审计技能；聚焦 SQL 注入模式并输出结构化执行证据。
---

# SQL Injection Audit

仅执行 `SQLI` 类别审计，用于 must-cover 并行层。

## 输入

接收 `AuditWorkItem(category_id=SQLI)`：

- `target_files`
- `exclude_rules`
- `required_sinks`
- `required_sources`
- `stop_conditions`
- `budget`

**模式清单（必读取）**：执行前必须 `Read` `./reports/pattern-manifest.json`。仅处理其中 `category == SQLI` 的 `patterns`；`patterns_loaded` **必须**与该集合的 `pattern_id` 列表一致。

## 检查范围

- SQL 字符串拼接
- `fmt.Sprintf` 组装 SQL
- ORM 动态语句（Raw/Exec/Order/Where 字符串）
- 参数化缺失与白名单缺失

## 执行要求

1. 以 sink 优先方式扫描（`database/sql`、gorm、sqlx、ent 等）。
2. 对每个命中点判断：
   - Source 是否可控
   - 是否存在有效参数化/净化
   - 是否属于误报（框架自动防护）
3. 无发现时输出 `no_finding_evidence`，禁止空结果无说明。

## 输出

返回 `AgentResult`：

```yaml
agent_type: sqli
files_scanned: []
patterns_loaded: []
patterns_executed: []
sink_hits: []
findings: []
static_findings: []   # 默认 []；仅当某类问题无污点模型时写入 static_only 项
no_finding_evidence: ""
errors: []
```

并且必须附带 `sink_candidates`（供父层 `trace-resolver` 污点轨）：

```yaml
sink_candidates:
  - id: string
    category_id: SQLI
    evidence_model: taint_traceable | static_only   # 可选；省略 = taint_traceable（SQLI 多数为污点轨）
    file: path
    function: func
    sink: api
    line: number
    sink_snippet: string
    suspected_sources: [string]
    taint_hints: [string]
    confidence: low | medium | high
```

**默认**：拼接 SQL、ORM Raw 等仍以污点轨为主（省略 `evidence_model` 或 `taint_traceable`）。仅当某结论明确无污点模型时，使用 `static_findings` + `evidence_model: static_only`。

## 模式追溯中间 JSON（必落盘）

必须写入：`./reports/intermediate/<run_id>/sqli-audit.json`（`run_id` 与 `must-cover-results.json` 一致；`mkdir -p` 同 file-audit）。

字段与 `pattern_execution` 义务同 [pattern-coverage-json-schema.md](../orchestrator-audit/references/pattern-coverage-json-schema.md)。**每个** manifest 中 SQLI 的 `pattern_id` 须在 `pattern_execution` 中有一条记录。

## 硬性约束

- 只审 SQLI，不扩展到 FILE_OPS/GO_RUNTIME。
- 不生成最终报告，只返回结构化结果。
- 禁止直接调用 MCP；source->sink 追踪由父层 `trace-resolver` 对污点轨候选执行。
- **不得**省略 `sqli-audit.json`；缺失则 orchestrator **Gate-P** 失败。
