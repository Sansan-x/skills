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

## 检查范围

- panic 触发拒绝服务路径
- 资源耗尽（大对象分配、解压炸弹、无限读取）
- 竞态条件（共享状态无锁保护）
- 并发生命周期缺陷（释放后使用、goroutine 泄漏）

## 执行要求

1. 结合 Go 特有模式（`panic/recover`、`sync`、`context`、`unsafe`）进行审查。
2. 记录可利用证据与缓解措施有效性。
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
no_finding_evidence: ""
errors: []
```

## 硬性约束

- 只审 GO_RUNTIME，不扩展到 FILE_OPS/SQLI。
- 不生成最终报告，只返回结构化结果。
