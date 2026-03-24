# 漏洞字段规范

归一化漏洞JSON的完整逐字段规范说明。

## 目录

1. [基本标识](#基本标识)
2. [基本信息](#基本信息)
3. [漏洞描述](#漏洞描述)
4. [漏洞代码](#漏洞代码)
5. [数据流路径](#数据流路径)
6. [利用场景](#利用场景)
7. [影响](#影响)
8. [修复建议](#修复建议)
9. [人工确认](#人工确认)
10. [元数据](#元数据)
11. [JSON Schema 验证规范](#json-schema-验证规范)

---

## 基本标识

| 字段      | 类型   | 是否必填 | 允许值/格式                  | 说明                                                                |
| --------- | ------ | -------- | ---------------------------- | ------------------------------------------------------------------- |
| `vuln_id` | string | **是**   | `VULN-NNN` 格式              | 漏洞唯一标识符。优先使用报告中已有的编号；若无，则自动生成递增编号。 |
| `task_id` | string | **是**   | 自由格式字符串               | 该漏洞所属的 OpenCodeAuditTask ID，通常在报告元数据或头部中可找到。  |

**提取提示：**
- 在标题中查找 `VULN-001`、`漏洞编号: VULN-001`、`#VULN-001` 等模式。
- `task_id` 可能出现在报告前置信息、元数据表格或首段中。

---

## 基本信息

| 字段            | 类型    | 是否必填 | 允许值/格式                                                                    | 说明                                 |
| --------------- | ------- | -------- | ------------------------------------------------------------------------------ | ------------------------------------ |
| `severity`      | string  | **是**   | `致命` \| `严重` \| `一般` \| `提示`                                           | 严重性等级，英文对照见下方映射表。    |
| `cvss_score`    | number  | 否       | 0.0 – 10.0                                                                    | CVSS v3.x 基础评分。                |
| `cvss_vector`   | string  | 否       | CVSS向量字符串，如 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`            | 完整的 CVSS 向量。                   |
| `cwe`           | string  | 否       | `CWE-<编号>` 后可跟描述                                                        | CWE 标识和名称，如 `CWE-89: SQL Injection`。 |
| `confidence`    | string  | 否       | `确认` \| `高` \| `中` \| `低`                                                 | 检测置信度。                         |
| `location`      | string  | 否       | `<文件路径>:<行号> <函数名>`                                                    | 人类可读的位置字符串。               |
| `file_path`     | string  | 否       | 文件路径                                                                       | 漏洞文件的相对路径。                 |
| `line_start`    | integer | 否       | 正整数                                                                         | 漏洞代码起始行号。                   |
| `line_end`      | integer | 否       | 正整数，≥ `line_start`                                                         | 漏洞代码结束行号。                   |
| `function_name` | string  | 否       | 函数/方法名称                                                                  | 包含漏洞的函数名。                   |

### 严重性映射参考

| 英文标签                | 中文标签                     | 归一化值   |
| ----------------------- | ---------------------------- | ---------- |
| Critical / P0           | 致命 / 紧急                   | `致命`     |
| High / P1               | 高危 / 严重 / 高              | `严重`     |
| Medium / P2             | 中危 / 中等 / 一般            | `一般`     |
| Low / Info / P3 / P4    | 低危 / 低 / 提示 / 信息       | `提示`     |

### 置信度映射参考

| 英文标签    | 归一化值 |
| ----------- | -------- |
| Confirmed   | `确认`   |
| High        | `高`     |
| Medium      | `中`     |
| Low         | `低`     |

---

## 漏洞描述

| 字段                    | 类型   | 是否必填 | 说明                                                             |
| ----------------------- | ------ | -------- | ---------------------------------------------------------------- |
| `vulnerability_title`   | string | **是**   | 简短的漏洞标题，使用报告中的标题。                                |
| `vulnerability_essence` | string | 否       | 一句话概括漏洞的*本质*是什么。                                    |
| `root_cause`            | string | 否       | 漏洞产生的根本原因——底层的编程错误或设计缺陷。                    |
| `security_impact`       | string | 否       | 攻击者利用此漏洞能实现什么。                                      |

**提取提示：**
- `vulnerability_title` 通常为每个发现的子标题。
- `vulnerability_essence` 可能标注为"漏洞本质"、"概述"或"Summary"。
- `root_cause` 可能标注为"根因"、"根因分析"、"原因分析"或"Root Cause"，也可能出现在"分析"章节中。
- `security_impact` 可能标注为"安全影响"、"危害"、"Impact"或"Risk"。

---

## 漏洞代码

| 字段              | 类型   | 是否必填 | 说明                                                   |
| ----------------- | ------ | -------- | ------------------------------------------------------ |
| `vulnerable_code` | string | 否       | 展示漏洞的代码片段，逐字保留原始格式。                  |

**提取提示：**
- 通常位于漏洞描述附近的围栏代码块（` ``` `）中。
- 保留语言标签（如 `python`、`java`）。
- 若存在多个代码块，使用最接近漏洞标题或明确标注为"漏洞代码"的那个。

---

## 数据流路径

| 字段                     | 类型          | 是否必填 | 说明                                                                           |
| ------------------------ | ------------- | -------- | ------------------------------------------------------------------------------ |
| `dataflow_source`        | string        | 否       | 污点源——不可信数据的入口（如HTTP参数、文件输入）。                               |
| `dataflow_propagation`   | array[string] | 否       | 从源到汇聚点的有序传播步骤列表。每个元素是一个代码表达式或步骤描述。             |
| `dataflow_sink`          | string        | 否       | 消费污点数据的危险函数调用（如 `cursor.execute()`、`eval()`）。                  |
| `dataflow_sanitization`  | string        | 否       | 已应用的净化或验证措施的描述（或说明缺乏净化措施）。                             |
| `dataflow_conclusion`    | string        | 否       | 污点分析的总结结论。                                                           |

**提取提示：**
- 查找标注为"数据流分析"、"污点分析"、"Taint Analysis"、"Data Flow"、"Source-Sink"的章节。
- `dataflow_propagation` 序列化为 JSON 字符串数组，每个步骤对应一个元素。

---

## 利用场景

| 字段            | 类型   | 是否必填 | 说明                                         |
| --------------- | ------ | -------- | -------------------------------------------- |
| `exploit_steps` | string | 否       | 逐步的攻击描述，可以是编号列表或叙述性文本。  |
| `exploit_poc`   | string | 否       | 概念验证（PoC）代码或命令。                   |

**提取提示：**
- 查找标注为"利用方式"、"利用场景"、"攻击步骤"、"Exploitation"、"PoC"、"Proof of Concept"的章节。
- 保留 `exploit_poc` 中的代码块格式。

---

## 影响

| 字段                     | 类型   | 是否必填 | 允许值              | 说明             |
| ------------------------ | ------ | -------- | ------------------- | ---------------- |
| `impact_confidentiality` | string | 否       | `高` \| `中` \| `低` | 对数据机密性的影响。 |
| `impact_integrity`       | string | 否       | `高` \| `中` \| `低` | 对数据完整性的影响。 |
| `impact_availability`    | string | 否       | `高` \| `中` \| `低` | 对系统可用性的影响。 |

**英文映射：** High→高，Medium→中，Low→低。

---

## 修复建议

| 字段              | 类型   | 是否必填 | 说明                           |
| ----------------- | ------ | -------- | ------------------------------ |
| `fix_description` | string | 否       | 如何修复漏洞的文字说明。        |
| `fix_code_before` | string | 否       | 漏洞代码片段（修复前）。        |
| `fix_code_after`  | string | 否       | 安全代码片段（修复后）。        |

**提取提示：**
- 查找标注为"修复建议"、"修复方案"、"修复说明"、"Remediation"、"Fix"、"Recommendation"的章节。
- 修复前后的代码块通常依次呈现或并列展示。

---

## 人工确认

| 字段                         | 类型   | 是否必填 | 允许值/格式                                       | 说明                                   |
| ---------------------------- | ------ | -------- | ------------------------------------------------- | -------------------------------------- |
| `manual_confirmation`        | string | 否       | 自由格式文本                                       | 人工确认备注。                          |
| `manual_confirmation_status` | string | 否       | `待确认` \| `已确认` \| `误报` \| `已修复`         | 确认状态。默认值：`待确认`。            |
| `manual_confirmation_notes`  | string | 否       | 自由格式文本                                       | 确认人的额外备注。                      |
| `confirmed_by`               | string | 否       | 用户ID / 姓名                                     | 确认人标识。                            |
| `confirmed_at`               | string | 否       | ISO-8601 日期时间                                  | 确认时间。                              |

**默认值：**
- 若报告中不包含确认信息，`manual_confirmation_status` 设为 `待确认`，
  其余确认字段均设为 `null`。

---

## 元数据

| 字段         | 类型   | 是否必填 | 允许值/格式                                              | 说明                                              |
| ------------ | ------ | -------- | -------------------------------------------------------- | ------------------------------------------------- |
| `status`     | string | 否       | `new` \| `analyzing` \| `resolved` \| `false_positive`   | 当前处理状态。默认值：`new`。                      |
| `created_at` | string | **是**   | ISO-8601 日期时间，如 `2025-01-15T10:30:00+08:00`        | 漏洞记录创建时间。使用报告日期或当前时间。          |
| `updated_at` | string | 否       | ISO-8601 日期时间                                        | 记录最后更新时间。初始值与 `created_at` 相同。      |

---

## JSON Schema 验证规范

以下 JSON Schema 可用于验证输出文件的格式正确性：

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "审计报告归一化输出格式",
  "description": "代码审计报告归一化后的结构化漏洞数据",
  "type": "object",
  "required": ["report_name", "total_vulnerabilities", "reports", "vulnerabilities"],
  "properties": {
    "report_name": {
      "type": "string",
      "description": "审计报告名称"
    },
    "report_date": {
      "type": "string",
      "format": "date-time",
      "description": "报告日期，ISO-8601格式"
    },
    "total_vulnerabilities": {
      "type": "integer",
      "minimum": 0,
      "description": "漏洞总数"
    },
    "severity_summary": {
      "type": "object",
      "description": "按严重性等级汇总",
      "properties": {
        "致命": { "type": "integer", "description": "致命级别漏洞数量" },
        "严重": { "type": "integer", "description": "严重级别漏洞数量" },
        "一般": { "type": "integer", "description": "一般级别漏洞数量" },
        "提示": { "type": "integer", "description": "提示级别漏洞数量" }
      }
    },
    "reports": {
      "type": "array",
      "description": "来源报告列表（单报告时仅一个元素，多报告时记录各报告信息）",
      "items": {
        "type": "object",
        "required": ["source_report"],
        "properties": {
          "source_report": { "type": "string", "description": "来源报告文件名" },
          "report_date":   { "type": ["string", "null"], "format": "date-time", "description": "该报告日期" },
          "task_id":       { "type": ["string", "null"], "description": "该报告关联的任务ID" }
        }
      }
    },
    "vulnerabilities": {
      "type": "array",
      "description": "漏洞详情列表",
      "items": {
        "type": "object",
        "required": ["vuln_id", "task_id", "severity", "vulnerability_title", "created_at"],
        "properties": {
          "vuln_id":                    { "type": "string", "description": "漏洞ID" },
          "task_id":                    { "type": "string", "description": "关联的审计任务ID" },
          "severity":                   { "type": "string", "enum": ["致命", "严重", "一般", "提示"], "description": "严重性等级" },
          "cvss_score":                 { "type": ["number", "null"], "description": "CVSS评分" },
          "cvss_vector":                { "type": ["string", "null"], "description": "CVSS向量字符串" },
          "cwe":                        { "type": ["string", "null"], "description": "CWE编号和描述" },
          "confidence":                 { "type": ["string", "null"], "enum": ["确认", "高", "中", "低", null], "description": "置信度" },
          "location":                   { "type": ["string", "null"], "description": "位置（文件路径:行号 函数名）" },
          "file_path":                  { "type": ["string", "null"], "description": "文件路径" },
          "line_start":                 { "type": ["integer", "null"], "description": "起始行号" },
          "line_end":                   { "type": ["integer", "null"], "description": "结束行号" },
          "function_name":              { "type": ["string", "null"], "description": "函数名" },
          "vulnerability_title":        { "type": "string", "description": "漏洞标题" },
          "vulnerability_essence":      { "type": ["string", "null"], "description": "漏洞本质" },
          "root_cause":                 { "type": ["string", "null"], "description": "根因分析" },
          "security_impact":            { "type": ["string", "null"], "description": "安全影响" },
          "vulnerable_code":            { "type": ["string", "null"], "description": "漏洞代码片段" },
          "dataflow_source":            { "type": ["string", "null"], "description": "污点源（Source）" },
          "dataflow_propagation":       { "type": ["array", "null"], "items": { "type": "string" }, "description": "传播路径（JSON数组）" },
          "dataflow_sink":              { "type": ["string", "null"], "description": "汇聚点（Sink）" },
          "dataflow_sanitization":      { "type": ["string", "null"], "description": "净化检查" },
          "dataflow_conclusion":        { "type": ["string", "null"], "description": "数据流结论" },
          "exploit_steps":              { "type": ["string", "null"], "description": "攻击步骤" },
          "exploit_poc":                { "type": ["string", "null"], "description": "概念验证（PoC）" },
          "impact_confidentiality":     { "type": ["string", "null"], "enum": ["高", "中", "低", null], "description": "机密性影响" },
          "impact_integrity":           { "type": ["string", "null"], "enum": ["高", "中", "低", null], "description": "完整性影响" },
          "impact_availability":        { "type": ["string", "null"], "enum": ["高", "中", "低", null], "description": "可用性影响" },
          "fix_description":            { "type": ["string", "null"], "description": "修复说明" },
          "fix_code_before":            { "type": ["string", "null"], "description": "修复前代码" },
          "fix_code_after":             { "type": ["string", "null"], "description": "修复后代码" },
          "manual_confirmation":        { "type": ["string", "null"], "description": "人工确认结果" },
          "manual_confirmation_status": { "type": ["string", "null"], "enum": ["待确认", "已确认", "误报", "已修复", null], "description": "确认状态" },
          "manual_confirmation_notes":  { "type": ["string", "null"], "description": "确认备注" },
          "confirmed_by":               { "type": ["string", "null"], "description": "确认人ID" },
          "confirmed_at":               { "type": ["string", "null"], "format": "date-time", "description": "确认时间" },
          "status":                     { "type": ["string", "null"], "enum": ["new", "analyzing", "resolved", "false_positive", null], "description": "处理状态" },
          "created_at":                 { "type": "string", "format": "date-time", "description": "创建时间" },
          "updated_at":                 { "type": ["string", "null"], "format": "date-time", "description": "更新时间" }
        }
      }
    }
  }
}
```

---

## 字段完整性一览

以下表格汇总全部字段，便于快速查阅：

| 字段分类   | 字段名称                     | 类型          | 是否必填 | 说明                                          |
| ---------- | ---------------------------- | ------------- | -------- | --------------------------------------------- |
| **基本标识** | vuln_id                    | string        | 是       | 漏洞ID（如VULN-001）                          |
|            | task_id                    | string        | 是       | 关联的OpenCodeAuditTask ID                    |
| **基本信息** | severity                   | string        | 是       | 严重性（致命/严重/一般/提示）                 |
|            | cvss_score                 | number        | 否       | CVSS评分（如9.8）                             |
|            | cvss_vector                | string        | 否       | CVSS向量字符串                                |
|            | cwe                        | string        | 否       | CWE编号和描述                                 |
|            | confidence                 | string        | 否       | 置信度（确认/高/中/低）                       |
|            | location                   | string        | 否       | 位置（文件路径:行号 函数名）                  |
|            | file_path                  | string        | 否       | 文件路径                                      |
|            | line_start                 | integer       | 否       | 起始行号                                      |
|            | line_end                   | integer       | 否       | 结束行号                                      |
|            | function_name              | string        | 否       | 函数名                                        |
| **漏洞描述** | vulnerability_title        | string        | 是       | 漏洞标题                                      |
|            | vulnerability_essence      | string        | 否       | 漏洞本质                                      |
|            | root_cause                 | string        | 否       | 根因分析                                      |
|            | security_impact            | string        | 否       | 安全影响                                      |
| **漏洞代码** | vulnerable_code            | string        | 否       | 漏洞代码片段                                  |
| **数据流路径** | dataflow_source          | string        | 否       | 污点源（Source）                              |
|            | dataflow_propagation       | array[string] | 否       | 传播路径（JSON数组）                          |
|            | dataflow_sink              | string        | 否       | 汇聚点（Sink）                                |
|            | dataflow_sanitization      | string        | 否       | 净化检查                                      |
|            | dataflow_conclusion        | string        | 否       | 数据流结论                                    |
| **利用场景** | exploit_steps              | string        | 否       | 攻击步骤                                      |
|            | exploit_poc                | string        | 否       | 概念验证（PoC）                               |
| **影响**   | impact_confidentiality     | string        | 否       | 机密性影响（高/中/低）                        |
|            | impact_integrity           | string        | 否       | 完整性影响（高/中/低）                        |
|            | impact_availability        | string        | 否       | 可用性影响（高/中/低）                        |
| **修复建议** | fix_description            | string        | 否       | 修复说明                                      |
|            | fix_code_before            | string        | 否       | 修复前代码                                    |
|            | fix_code_after             | string        | 否       | 修复后代码                                    |
| **人工确认** | manual_confirmation        | string        | 否       | 人工确认结果                                  |
|            | manual_confirmation_status | string        | 否       | 确认状态（待确认/已确认/误报/已修复）         |
|            | manual_confirmation_notes  | string        | 否       | 确认备注                                      |
|            | confirmed_by               | string        | 否       | 确认人ID                                      |
|            | confirmed_at               | string        | 否       | 确认时间                                      |
| **元数据** | status                     | string        | 否       | 状态（new/analyzing/resolved/false_positive） |
|            | created_at                 | string        | 是       | 创建时间                                      |
|            | updated_at                 | string        | 否       | 更新时间                                      |
