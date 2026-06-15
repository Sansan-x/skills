---
name: file-audit
description: 高危必覆盖 FILE_OPS 审计技能；聚焦路径与文件系统相关漏洞模式并输出结构化执行证据。
---

# File Operations Audit

仅执行 `FILE_OPS` 类别审计，用于 must-cover 并行层。

## 输入

接收 `AuditWorkItem(category_id=FILE_OPS)`：

- `target_files`
- `exclude_rules`
- `required_sinks`
- `required_sources`
- `stop_conditions`
- `budget`

**模式清单（必读取）**：执行前必须 `Read` `./reports/pattern-manifest.json`（与 [pattern-coverage-json-schema.md](../orchestrator-audit/references/pattern-coverage-json-schema.md) 一致）。仅处理其中 `category == FILE_OPS` 的 `patterns`；`patterns_loaded` **必须**与该集合的 `pattern_id` 列表一致（不得遗漏 manifest 中的 FILE_OPS 条目）。

## 参考文件

- `skills/file-audit/references/file-ops-vulnerability-patterns.md`（FILE_OPS 专属漏洞模式库）

## 检查范围

- 路径穿越（CWE-22）与 Zip Slip
- 上传文件校验缺失（扩展名、MIME、magic bytes）
- 权限过宽（如 `0777` / `0666`）
- 符号链接绕过与临时文件不安全创建
- 上述检查项的模式与示例以 FILE_OPS 专属 references 为准

## 执行要求

1. 读取 `target_files` 并执行模式匹配 + 语义验证。
2. 对每个命中点记录：
   - `file/function/line`
   - `source/sink`
   - 净化或防护是否有效
3. 无发现时仍必须输出可复核的 `no_finding_evidence`（例如已扫描文件数、关键 sink 检索摘要）。

## 输出

返回 `AgentResult`：

```yaml
agent_type: file
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
    category_id: FILE_OPS
    evidence_model: taint_traceable | static_only   # 可选；省略 = taint_traceable（FILE_OPS 多数为污点轨）
    file: path
    function: func
    sink: api
    line: number
    sink_snippet: string
    suspected_sources: [string]
    taint_hints: [string]
    confidence: low | medium | high
```

**默认**：路径穿越、Zip Slip 等仍以污点轨为主（省略 `evidence_model` 或 `taint_traceable`）。仅当某结论明确无污点模型时，使用 `static_findings` + `evidence_model: static_only`，且勿再为其排队 MCP。

## 模式追溯中间 JSON（必落盘）

除返回内存中的 `AgentResult` 外，必须写入：

`./reports/intermediate/<run_id>/file-audit.json`

- `run_id`：与编排层写入 `must-cover-results.json` 的 `run_id` **相同**（由 orchestrator / 父流程下发或约定为 `YYYYMMDD-HHMM` UTC）。
- 落盘前执行：`mkdir -p "./reports/intermediate/<run_id>"`。
- JSON 顶层字段与 `pattern_execution[]` 语义见 [pattern-coverage-json-schema.md](../orchestrator-audit/references/pattern-coverage-json-schema.md)。
- **`pattern_execution` 覆盖义务**：对 `patterns_loaded` 中**每一个** `pattern_id` 必须有一条记录；`status` 为 `executed_hit` / `executed_no_hit` / `skipped` / `blocked` 之一；`skipped`/`blocked` 必须填 `skip_reason_code`（允许枚举见 schema）。
- `patterns_executed` 数组必须等于「`pattern_execution` 中 `status` 为 `executed_hit` 或 `executed_no_hit` 的 `pattern_id`」集合（与 YAML 中 `patterns_executed` 一致）。
- `evidence_refs`：命中写 `finding:<id>` / `sink:<id>` / `static:<id>`；无命中可省略或留空数组。

## 硬性约束

- 只审 FILE_OPS，不扩展到 SQLI/GO_RUNTIME。
- 不生成最终报告，只返回结构化结果。
- 禁止直接调用 MCP；source->sink 追踪由父层 `trace-resolver` 对污点轨候选执行。
- **不得**省略 `file-audit.json`；缺失则 orchestrator **Gate-P** 失败。
