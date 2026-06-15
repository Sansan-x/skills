---
name: go-unique-patterns-extra
description: GO_RUNTIME 增强审计技能；在 go-runtime-audit 后执行，补充 Go 语言特有攻击面并输出结构化执行证据。
---

# Go Unique Patterns Extra Audit

作为 `go-runtime-audit` 的后置增强技能执行，仅执行 `GO_RUNTIME` 类别审计并补充 Go 语言特有攻击面。

## 输入

接收 `AuditWorkItem(category_id=GO_RUNTIME)`：

- `target_files`
- `exclude_rules`
- `required_sinks`
- `required_sources`
- `stop_conditions`
- `budget`

**模式清单（必读取）**：执行前必须 `Read` `./reports/pattern-manifest.json`。仅认领 `category == GO_RUNTIME` **且** `source_ref` 路径子串包含 `go-language-unique-patterns-extra.md`（或仓库内 `./references/go-language-unique-patterns-extra.md` / `skills/go-unique-patterns-extra/references/`）的 `patterns`；`patterns_loaded` **必须**等于该子集的 `pattern_id` 全集。

## 检查范围

参考 `../go-audit-common/references/go-language-unique-patterns-extra.md`，重点关注：

- goroutine / channel 生命周期泄漏与阻塞
- context 传递、超时、取消链路缺失
- slice header / cap 底层共享导致泄露
- map / sync.Map 复合操作竞态
- unsafe / reflect / cgo 的类型与生命周期风险
- go:generate / init 的隐藏执行与副作用

## 执行要求

1. 仅补充执行 Go 特有攻击面，不覆盖或重写前置 `go-runtime-audit` 已确认结论。
2. 与前置技能保持同一数据契约；结论冲突时必须在 `errors` 记录原因，禁止静默覆盖。
3. 无发现时必须输出 `no_finding_evidence` 与扫描摘要。

## 输出

返回 `AgentResult`：

```yaml
agent_type: go-runtime
files_scanned: []
patterns_loaded: []
patterns_executed: []
sink_hits: []
findings: []
static_findings: []
no_finding_evidence: ""
errors: []
```

并且必须附带 `sink_candidates`：

```yaml
sink_candidates:
  - id: string
    category_id: GO_RUNTIME
    evidence_model: taint_traceable | static_only
    file: path
    function: func
    sink: api
    line: number
    sink_snippet: string
    suspected_sources: [string]
    taint_hints: [string]
    confidence: low | medium | high
```

说明：

- Panic / DoS / 竞态 / 生命周期缺陷等不可污点化结论优先进入 `static_findings`（`evidence_model: static_only`）。
- 若存在清晰用户输入传播路径，可额外输出 `sink_candidates`（`evidence_model` 省略或 `taint_traceable`）。
- `static_findings` 与 `sink_candidates` 不得对同一位置给出互相矛盾结论。

## 模式追溯中间 JSON（必落盘）

必须写入：`./reports/intermediate/<run_id>/go-unique-patterns-extra.json`（`run_id` 与 `must-cover-results.json` 一致）。

- 顶层 `agent` 固定为 `go-unique-patterns-extra`，`category_id` 为 `GO_RUNTIME`。
- `pattern_execution` 须覆盖本技能认领的全部 `patterns_loaded`；契约见 [pattern-coverage-json-schema.md](../orchestrator-audit/references/pattern-coverage-json-schema.md)。

## 参考文件

- `./references/go-language-unique-patterns-extra.md`

## 硬性约束

- 只审 `GO_RUNTIME`，不得扩展到 `FILE_OPS` / `SQLI`。
- 不生成最终报告，只返回结构化结果。
- 禁止直接调用 MCP；source->sink 追踪由父层 `trace-resolver` 统一执行。
- **不得**省略 `go-unique-patterns-extra.json`；缺失则 orchestrator **Gate-P** 失败。
