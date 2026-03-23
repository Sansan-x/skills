---
name: Audit_report_normalization
description: >
  Normalize code audit reports and extract vulnerability data into structured JSON.
  Use this skill whenever the user wants to parse, normalize, or extract vulnerabilities
  from a markdown-format code audit report, convert audit findings to JSON for database storage,
  consolidate multiple audit reports, or produce structured vulnerability data from free-form
  security audit results. Also trigger when the user mentions terms like "audit report",
  "vulnerability extraction", "security findings normalization", "audit JSON", or
  "漏洞提取", "审计报告归一化", "审计报告解析", "代码审计结果整合".
---

# Audit Report Normalization (审计报告归一化)

Parse markdown-format code audit reports, extract each discovered vulnerability into a
well-defined JSON structure, and output the result as `<报告名称>.json` for easy database
ingestion.

## When to Use This Skill

- The user provides one or more markdown code-audit reports and wants structured output.
- The user asks to "normalize", "parse", "extract", or "convert" audit findings.
- The user needs vulnerability data in JSON for storage, analysis, or integration with
  a vulnerability management system.

## High-Level Workflow

1. **Receive the audit report** — the user supplies a `.md` file (or pastes markdown
   content). Identify the report name from the filename or the first top-level heading.
2. **Understand report structure** — scan the report for section patterns that delineate
   individual vulnerabilities (e.g., headings like `## VULN-001`, `### 漏洞 1`, numbered
   findings, or table rows).
3. **Extract vulnerability fields** — for each vulnerability found, populate the fields
   defined in the schema below. Required fields must always be present; optional fields
   should be included when the data exists in the report.
4. **Generate JSON output** — write the result to `<审计报告名称>.json` following the
   output format described below.

## Vulnerability Field Schema

Consult `references/vuln-schema.md` for the full field-by-field specification including
types, allowed values, and examples. Below is a quick-reference summary.

### Required Fields

| Field                | Type   | Description                        |
| -------------------- | ------ | ---------------------------------- |
| `vuln_id`            | string | Unique ID, e.g. `VULN-001`        |
| `task_id`            | string | Associated OpenCodeAuditTask ID    |
| `severity`           | string | 致命 / 严重 / 一般 / 提示          |
| `vulnerability_title`| string | Short title of the vulnerability   |
| `created_at`         | string | ISO-8601 timestamp                 |

### Optional Fields (include when data is available)

Grouped into: 基本信息, 漏洞描述, 漏洞代码, 数据流路径, 利用场景, 影响,
修复建议, 人工确认, 元数据. See `references/vuln-schema.md` for the complete list.

## Extraction Rules

Follow these rules when mapping report content to JSON fields:

### 1. Identification & Severity

- **vuln_id**: Use the ID from the report (e.g. `VULN-001`). If none exists, generate
  sequential IDs in the form `VULN-NNN`.
- **task_id**: Use the task ID stated in the report header/metadata. If not found, ask
  the user or use a placeholder `TASK-UNKNOWN`.
- **severity**: Map report language to the four-level scale:
  - 致命 (Critical) — remote code execution, authentication bypass, etc.
  - 严重 (High) — SQL injection, XSS with significant impact, etc.
  - 一般 (Medium) — information disclosure, CSRF, etc.
  - 提示 (Info/Low) — best-practice violations, minor issues.
  If the report uses English severity labels (Critical/High/Medium/Low/Info),
  translate to the Chinese equivalents above.

### 2. Location Fields

- Parse patterns like `path/to/file.py:42` or `文件: xxx.py 行号: 42-50 函数: foo()`.
- Populate `file_path`, `line_start`, `line_end`, `function_name` individually *and*
  compose the human-readable `location` string (`file_path:line_start function_name`).

### 3. CVSS and CWE

- Extract CVSS score (float), CVSS vector string, and CWE identifiers when present.
- Recognize patterns like `CVSS: 9.8`, `CVSS:3.1/AV:N/AC:L/...`, `CWE-89`, `CWE-79: Cross-Site Scripting`.

### 4. Vulnerability Description

- `vulnerability_title`: The heading or first sentence summarizing the vuln.
- `vulnerability_essence`: A concise statement of *what* the vulnerability is.
- `root_cause`: Why the vulnerability exists (e.g. missing input validation).
- `security_impact`: What an attacker can achieve.

### 5. Code & Data-Flow

- `vulnerable_code`: Extract the code snippet verbatim (preserve formatting).
- Data-flow fields (`dataflow_source`, `dataflow_propagation`, `dataflow_sink`,
  `dataflow_sanitization`, `dataflow_conclusion`): Populate from taint-analysis or
  data-flow sections of the report. `dataflow_propagation` should be a JSON array
  of steps.

### 6. Exploit & Impact

- `exploit_steps`: Ordered attack steps as a string or list.
- `exploit_poc`: Proof-of-concept code, if provided.
- CIA impact fields (`impact_confidentiality`, `impact_integrity`,
  `impact_availability`): Map to 高/中/低.

### 7. Fix Suggestions

- `fix_description`: Narrative fix guidance.
- `fix_code_before` / `fix_code_after`: Before/after code snippets.

### 8. Manual Confirmation

- Default `manual_confirmation_status` to `待确认` unless the report states otherwise.
- Leave `confirmed_by` and `confirmed_at` empty if not provided.

### 9. Metadata

- `status`: Default to `new` unless stated otherwise.
- `created_at`: Use the report's date or the current timestamp in ISO-8601.
- `updated_at`: Set to `created_at` initially.

## Output Format

The output JSON file must follow this structure:

```json
{
  "report_name": "<审计报告名称>",
  "report_date": "<报告日期, ISO-8601>",
  "total_vulnerabilities": <漏洞总数>,
  "severity_summary": {
    "致命": <count>,
    "严重": <count>,
    "一般": <count>,
    "提示": <count>
  },
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
      "function_name": "execute_query",
      "vulnerability_title": "SQL注入漏洞",
      "vulnerability_essence": "用户输入直接拼接到SQL查询语句中",
      "root_cause": "未对用户输入进行参数化处理",
      "security_impact": "攻击者可执行任意SQL语句，读取/修改/删除数据库数据",
      "vulnerable_code": "query = \"SELECT * FROM users WHERE id = \" + user_input",
      "dataflow_source": "HTTP请求参数 user_id",
      "dataflow_propagation": ["request.args['user_id']", "user_input = request.args['user_id']", "query = 'SELECT ... ' + user_input"],
      "dataflow_sink": "cursor.execute(query)",
      "dataflow_sanitization": "无净化措施",
      "dataflow_conclusion": "污点数据从HTTP请求参数直接传播到SQL执行点，未经任何过滤",
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

### Naming Convention

The output file is named after the audit report: if the input is `项目A安全审计报告.md`,
the output is `项目A安全审计报告.json`.

## Handling Multiple Reports

When the user provides multiple audit reports:

1. Process each report independently.
2. Generate one JSON file per report.
3. Ensure `vuln_id` values are unique across all reports (prefix with report identifier
   if necessary, e.g. `REPORT-A-VULN-001`).
4. Optionally produce a merged summary file if the user requests consolidation.

## Edge Cases

- **Missing required fields**: If a required field cannot be determined from the report,
  set it to a descriptive placeholder (e.g. `"UNKNOWN"`) and note the gap in a
  `_parsing_notes` field on the vulnerability object.
- **Non-standard report formats**: If the markdown doesn't follow a recognizable
  vulnerability-by-vulnerability structure, attempt to identify individual findings by
  looking for severity keywords, CWE references, code blocks, or fix recommendations
  as boundaries between issues.
- **Mixed languages**: Reports may use Chinese, English, or a mix. Handle both
  seamlessly; output field names are always in English (snake_case) while values
  preserve the original language of the report content.

## Examples

See `examples/sample-audit-report.md` for a realistic input report and
`examples/sample-output.json` for the corresponding expected JSON output.

## Keywords

审计报告, 代码审计, 漏洞提取, 归一化, 安全审计, vulnerability extraction,
audit report normalization, security findings, JSON conversion, 漏洞数据库,
code audit report, 安全漏洞, CVSS, CWE
