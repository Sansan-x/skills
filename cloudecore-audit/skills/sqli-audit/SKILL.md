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
no_finding_evidence: ""
errors: []
```

并且必须附带 `sink_candidates`（供父层 `trace-resolver`）：

```yaml
sink_candidates:
  - id: string
    category_id: SQLI
    file: path
    function: func
    sink: api
    line: number
    sink_snippet: string
    suspected_sources: [string]
    taint_hints: [string]
    confidence: low | medium | high
```

## 硬性约束

- 只审 SQLI，不扩展到 FILE_OPS/GO_RUNTIME。
- 不生成最终报告，只返回结构化结果。
- 禁止直接调用 MCP；source->sink 追踪由父层 `trace-resolver` 执行。
