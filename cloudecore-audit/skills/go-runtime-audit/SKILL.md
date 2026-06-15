---
name: go-runtime-audit
description: 高危必覆盖 GO_RUNTIME 审计技能；聚焦 panic/DoS/竞态与并发生命周期问题并输出结构化执行证据。
---

# Go Runtime Security Audit

仅执行 `GO_RUNTIME` 类别审计，用于 must-cover 并行层。

## 输入

接收 `AuditWorkItem(category_id=GO_RUNTIME)`：

- `target_files`
- `exclude_rules`
- `required_sinks`
- `required_sources`
- `stop_conditions`
- `budget`

**模式清单（必读取）**：执行前必须 `Read` `./reports/pattern-manifest.json`。仅认领其中 `category == GO_RUNTIME` **且** `source_ref` 指向本技能模式库（路径子串包含 `go-runtime-vulnerability-patterns.md`）的 `patterns`；`patterns_loaded` **必须**等于该子集的 `pattern_id` 全集。若 manifest 未用文件名区分来源，则认领全部 `GO_RUNTIME` 条目并由后置技能对重复 `pattern_id` 在 `errors` 中说明（应避免；由 `project-analyzer` 在 `source_ref` 中区分文件）。

## 检查范围

- panic 触发拒绝服务路径
- 资源耗尽（大对象分配、解压炸弹、无限读取）
- 竞态条件（共享状态无锁保护）
- 并发生命周期缺陷（释放后使用、goroutine 泄漏）
- gRPC/Protobuf 安全缺陷（鉴权拦截器、元数据注入、反射暴露）
- Go Module 与依赖供应链风险（replace 劫持、typosquatting、已废弃依赖）

## 执行要求

1. 结合 Go 特有模式（`panic/recover`、`sync`、`context`、`unsafe`）进行审查。
2. 本技能完成后，由同级后置技能 `go-unique-patterns-extra` 继续补充 Go 语言特有攻击面深挖（同一 `GO_RUNTIME` 契约）。
3. 记录可利用证据与缓解措施有效性。
4. 无发现时必须输出 `no_finding_evidence` 与扫描摘要。

## 输出

返回 `AgentResult`：

```yaml
agent_type: go-runtime
files_scanned: []
patterns_loaded: []
patterns_executed: []
sink_hits: []
findings: []
static_findings: []   # 静态轨；Panic / 不变量 / 明显非污点模型命中必须写入此数组
no_finding_evidence: ""
errors: []
```

并且必须附带 `sink_candidates`（供父层 `trace-resolver` 污点轨）：

```yaml
sink_candidates:
  - id: string
    category_id: GO_RUNTIME
    evidence_model: taint_traceable | static_only   # 可选；省略 = taint_traceable
    file: path
    function: func
    sink: api
    line: number
    sink_snippet: string
    suspected_sources: [string]
    taint_hints: [string]
    confidence: low | medium | high
```

**Panic / DoS / 竞态等**：命中 **Panic** 或无可污点用户输入主路径的运行时陷阱时，**必须**写入 `static_findings`（`evidence_model: static_only`）。若同时存在清晰、可污点化的用户输入传播路径，可**额外**输出 `sink_candidate` 且 `evidence_model` 为缺省或 `taint_traceable`。`static_findings` 与 `sink_candidates` **不得**对同一行、同一结论给出互相矛盾的记录。

## 模式追溯中间 JSON（必落盘）

必须写入：`./reports/intermediate/<run_id>/go-runtime-audit-core.json`（`run_id` 与 `must-cover-results.json` 一致）。

- 顶层 `agent` 固定为 `go-runtime-audit`，`category_id` 为 `GO_RUNTIME`。
- `pattern_execution` 须覆盖本技能认领的全部 `patterns_loaded` 条目；字段见 [pattern-coverage-json-schema.md](../orchestrator-audit/references/pattern-coverage-json-schema.md)。

## 参考文件

- `./references/go-runtime-vulnerability-patterns.md`（GO_RUNTIME 专属漏洞攻击模式库，完整承接原通用库 18/19/20/21 章节）

## 硬性约束

- 只审 GO_RUNTIME，不扩展到 FILE_OPS/SQLI。
- 不生成最终报告，只返回结构化结果。
- 禁止直接调用 MCP；source->sink 追踪由父层 `trace-resolver` 对污点轨候选执行。
- **不得**省略 `go-runtime-audit-core.json`；缺失则 orchestrator **Gate-P** 失败。
