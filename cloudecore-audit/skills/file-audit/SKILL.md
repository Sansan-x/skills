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

## 检查范围

- 路径穿越（CWE-22）
- Zip Slip
- 上传文件校验缺失（CWE-434）
- 权限过宽（如 0777）
- 符号链接绕过与临时文件不安全创建

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
no_finding_evidence: ""
errors: []
```

## 硬性约束

- 只审 FILE_OPS，不扩展到 SQLI/GO_RUNTIME。
- 不生成最终报告，只返回结构化结果。
