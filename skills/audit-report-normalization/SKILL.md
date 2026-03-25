---
name: Audit_report_normalization
description: >
  审计报告归一化技能，用于解析Markdown格式的代码审计报告，提取漏洞数据并输出为结构化JSON。
  当用户需要解析、归一化或提取代码审计报告中的漏洞信息时使用此技能，包括：将审计发现转换为JSON
  以便存储到数据库、整合多份审计报告、从自由格式的安全审计结果中提取结构化漏洞数据等场景。
  触发关键词包括："审计报告"、"漏洞提取"、"审计报告归一化"、"审计报告解析"、"代码审计结果整合"、
  "audit report"、"vulnerability extraction"、"security findings normalization"。
---

# 审计报告归一化

解析Markdown格式的代码审计报告，逐一提取每个发现的漏洞并转换为规范的JSON结构，
最终统一输出为一份 `<审计报告名称>.json` 文件，便于入库存储和后续分析。
无论输入是单份还是多份审计报告，始终只生成一份JSON文件。

## 适用场景

- 用户提供一份或多份Markdown格式的代码审计报告，需要结构化输出
- 用户要求"归一化"、"解析"、"提取"或"转换"审计发现
- 用户需要将漏洞数据转为JSON格式，用于存储、分析或对接漏洞管理系统

## 整体工作流程

1. **接收审计报告** — 用户提供 `.md` 文件（或粘贴Markdown内容）。可以是
   单份报告，也可以是多份报告。从文件名或第一个顶级标题中识别报告名称。
2. **理解报告结构** — 扫描报告，识别用于划分单个漏洞的章节模式（例如：
   `## VULN-001` 这样的标题、`### 漏洞 1` 这样的编号发现、表格行等）。
3. **提取漏洞字段** — 对每个发现的漏洞，按照下述字段规范填充数据。必填字段必须
   始终存在；可选字段在报告中有相应数据时应包含。
4. **合并与生成** — 将所有报告中提取的漏洞汇总到一份JSON文件中，按照下方
   输出格式写入 `<审计报告名称>.json`。始终只输出一份JSON文件。

## 漏洞字段规范

完整的逐字段规范（包含类型、允许值和示例）请查阅 `references/vuln-schema.md`。
以下为快速参考摘要。

### 必填字段

| 字段                  | 类型   | 说明                             |
| --------------------- | ------ | -------------------------------- |
| `vuln_id`             | string | 漏洞唯一标识，如 `VULN-001`      |
| `task_id`             | string | 关联的 OpenCodeAuditTask ID      |
| `severity`            | string | 严重性：致命 / 严重 / 一般 / 提示 |
| `vulnerability_title` | string | 漏洞标题                         |
| `created_at`          | string | 创建时间，ISO-8601 格式          |

### 可选字段（存在相关数据时包含）

按分类分为：基本信息、漏洞描述、漏洞代码、数据流路径、利用场景、影响、
修复建议、人工确认、元数据。完整列表请查阅 `references/vuln-schema.md`。

## 提取规则

将报告内容映射到JSON字段时，遵循以下规则：

### 1. 标识与严重性

- **vuln_id**：使用报告中的漏洞编号（如 `VULN-001`）。若报告中无编号，
  则按 `VULN-NNN` 格式生成递增编号。
- **task_id**：使用报告头部/元数据中的任务ID。若未找到，询问用户或使用
  占位符 `TASK-UNKNOWN`。
- **severity**：将报告中的严重性描述映射到四级标准：
  - 致命（Critical）— 远程代码执行、认证绕过等
  - 严重（High）— SQL注入、具有重大影响的XSS等
  - 一般（Medium）— 信息泄露、CSRF等
  - 提示（Info/Low）— 最佳实践违规、轻微问题
  若报告使用英文严重性标签（Critical/High/Medium/Low/Info），
  翻译为上述对应的中文等级。

### 2. 位置字段

- 解析 `path/to/file.py:42` 或 `文件: xxx.py 行号: 42-50` 等模式。
- 分别填充 `file_path`、`line_start`、`line_end`，
  并组合生成可读的 `location` 字符串（`file_path:line_start`）。

### 3. CVSS 与 CWE

- 提取报告中的 CVSS 评分（浮点数）、CVSS 向量字符串和 CWE 标识符。
- 识别 `CVSS: 9.8`、`CVSS:3.1/AV:N/AC:L/...`、`CWE-89`、
  `CWE-79: Cross-Site Scripting` 等模式。

### 4. 漏洞描述

- `vulnerability_title`：漏洞的标题或概述性第一句话。
- `vulnerability_essence`：简明扼要地说明漏洞*本质是什么*。
- `root_cause`：漏洞产生的根本原因（如缺少输入验证）。
- `security_impact`：攻击者利用此漏洞能达到什么目的。

### 5. 代码与数据流

- `vulnerable_code`：逐字提取代码片段（保留原始格式）。
- `dataflow`：直接从审计报告中提取"数据流分析"/"数据流路径"/"污点分析"等
  章节的完整文本内容，作为一个字符串原样保留，不做拆分。若报告中无此章节则设为 `null`。

### 6. 利用场景与影响

- `exploit_steps`：有序的攻击步骤描述（字符串或列表）。
- `exploit_poc`：概念验证代码（如有提供）。
- CIA 影响字段（`impact_confidentiality`、`impact_integrity`、
  `impact_availability`）：映射为 高/中/低。

### 7. 修复建议

- `fix_description`：修复方案的文字说明。
- `fix_code_before` / `fix_code_after`：修复前后的代码对比。

### 8. 人工确认

- `manual_confirmation_status` 默认设为 `待确认`，除非报告中有明确的确认信息。
- `confirmed_by` 和 `confirmed_at` 在未提供时留空。

### 9. 元数据

- `status`：默认设为 `new`，除非报告中另有说明。
- `created_at`：使用报告日期或当前时间戳，ISO-8601 格式。
- `updated_at`：初始值设为与 `created_at` 相同。

## 输出格式

始终只输出**一份**JSON文件，遵循以下结构：

```json
{
  "report_name": "<审计报告名称>",
  "report_date": "<报告日期, ISO-8601>",
  "total_vulnerabilities": "<漏洞总数>",
  "severity_summary": {
    "致命": "<数量>",
    "严重": "<数量>",
    "一般": "<数量>",
    "提示": "<数量>"
  },
  "reports": [
    {
      "source_report": "<来源报告文件名>",
      "report_date": "<该报告日期>",
      "task_id": "<该报告关联的任务ID>"
    }
  ],
  "vulnerabilities": [
    {
      "vuln_id": "VULN-001",
      "task_id": "TASK-001",
      "severity": "严重",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-89: SQL Injection",
      "confidence": "高",
      "location": "src/db/query.py:42 execute_query()",
      "file_path": "src/db/query.py",
      "line_start": 42,
      "line_end": 55,
      "vulnerability_title": "SQL注入漏洞",
      "vulnerability_essence": "用户输入直接拼接到SQL查询语句中",
      "root_cause": "未对用户输入进行参数化处理",
      "security_impact": "攻击者可执行任意SQL语句，读取/修改/删除数据库数据",
      "vulnerable_code": "query = \"SELECT * FROM users WHERE id = \" + user_input",
      "dataflow": "污点源 (Source): HTTP请求参数 user_id\n传播路径:\n1. request.args['user_id'] — 用户输入进入应用\n2. user_input = request.args['user_id']\n3. query = 'SELECT ... ' + user_input\n汇聚点 (Sink): cursor.execute(query)\n净化检查: 无净化措施\n结论: 污点数据从HTTP请求参数直接传播到SQL执行点，未经任何过滤",
      "exploit_steps": "1. 构造恶意user_id参数\n2. 发送请求: GET /api/user?user_id=1 OR 1=1\n3. 获取所有用户数据",
      "exploit_poc": "curl 'http://target/api/user?user_id=1%20OR%201%3D1'",
      "impact_confidentiality": "高",
      "impact_integrity": "高",
      "impact_availability": "中",
      "fix_description": "使用参数化查询替代字符串拼接",
      "fix_code_before": "query = \"SELECT * FROM users WHERE id = \" + user_input",
      "fix_code_after": "query = \"SELECT * FROM users WHERE id = %s\"\ncursor.execute(query, (user_input,))",
      "manual_confirmation": null,
      "manual_confirmation_status": "待确认",
      "manual_confirmation_notes": null,
      "confirmed_by": null,
      "confirmed_at": null,
      "status": "new",
      "created_at": "2025-01-15T10:30:00+08:00",
      "updated_at": "2025-01-15T10:30:00+08:00"
    }
  ]
}
```

### 命名规范

输出文件以审计报告名称命名：若输入为 `项目A安全审计报告.md`，
则输出为 `项目A安全审计报告.json`。

### 单报告场景

- `reports` 数组仅包含一个元素。
- `report_name` 直接使用该报告名称。

### 多报告场景

当用户提供多份审计报告时，仍然只生成一份JSON文件：

1. 解析每份报告，提取各自的漏洞数据。
2. 将所有漏洞合并到同一个 `vulnerabilities` 数组中。
3. `reports` 数组记录每份来源报告的信息（文件名、日期、任务ID）。
4. `report_name` 使用汇总性名称（如"综合安全审计报告"或用户指定的名称）。
5. 确保 `vuln_id` 全局唯一——为不同来源报告的漏洞添加前缀
  （如 `报告A-VULN-001`、`报告B-VULN-001`）。
6. `total_vulnerabilities` 和 `severity_summary` 反映所有报告的汇总数据。

## 边界情况处理

- **缺失必填字段**：若某个必填字段无法从报告中确定，设置为描述性占位符
  （如 `"UNKNOWN"`），并在该漏洞对象的 `_parsing_notes` 字段中记录缺失说明。
- **非标准报告格式**：若Markdown不遵循可识别的逐漏洞结构，尝试通过查找
  严重性关键词、CWE引用、代码块或修复建议等作为漏洞之间的分界标志来识别
  各个发现。
- **中英文混合**：报告可能使用中文、英文或中英混合。无缝处理两种语言；
  输出的字段名始终为英文（snake_case），字段值保留报告内容的原始语言。

## 示例

请查阅 `examples/sample-audit-report.md` 获取真实的输入报告示例，
以及 `examples/sample-output.json` 获取对应的期望JSON输出。

## 关键词

审计报告, 代码审计, 漏洞提取, 归一化, 安全审计, 漏洞数据库,
安全漏洞, CVSS, CWE, 代码审计结果整合, 审计报告解析
