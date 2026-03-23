# Vulnerability Field Schema (漏洞字段规范)

Complete field-by-field specification for the normalized vulnerability JSON.

## Table of Contents

1. [基本标识 (Identification)](#基本标识-identification)
2. [基本信息 (Basic Information)](#基本信息-basic-information)
3. [漏洞描述 (Vulnerability Description)](#漏洞描述-vulnerability-description)
4. [漏洞代码 (Vulnerable Code)](#漏洞代码-vulnerable-code)
5. [数据流路径 (Data Flow Path)](#数据流路径-data-flow-path)
6. [利用场景 (Exploit Scenario)](#利用场景-exploit-scenario)
7. [影响 (Impact)](#影响-impact)
8. [修复建议 (Fix Suggestions)](#修复建议-fix-suggestions)
9. [人工确认 (Manual Confirmation)](#人工确认-manual-confirmation)
10. [元数据 (Metadata)](#元数据-metadata)

---

## 基本标识 (Identification)

| Field     | Type   | Required | Allowed Values / Format           | Description                          |
| --------- | ------ | -------- | --------------------------------- | ------------------------------------ |
| `vuln_id` | string | **Yes**  | `VULN-NNN` pattern                | Unique vulnerability identifier. Use the ID from the report if available; otherwise generate sequential IDs. |
| `task_id` | string | **Yes**  | Free-form string                  | The OpenCodeAuditTask ID that this vulnerability belongs to. Found in report metadata or header. |

**Extraction hints:**
- Look for patterns like `VULN-001`, `漏洞编号: VULN-001`, `#VULN-001` in headings.
- `task_id` may appear in report front-matter, a metadata table, or the first paragraph.

---

## 基本信息 (Basic Information)

| Field        | Type   | Required | Allowed Values / Format                        | Description |
| ------------ | ------ | -------- | ---------------------------------------------- | ----------- |
| `severity`   | string | **Yes**  | `致命` \| `严重` \| `一般` \| `提示`            | Severity level. Map English equivalents: Critical→致命, High→严重, Medium→一般, Low/Info→提示. |
| `cvss_score` | number | No       | 0.0 – 10.0                                     | CVSS v3.x base score. |
| `cvss_vector`| string | No       | CVSS vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Full CVSS vector. |
| `cwe`        | string | No       | `CWE-<number>` optionally followed by description | CWE identifier and name, e.g. `CWE-89: SQL Injection`. |
| `confidence` | string | No       | `确认` \| `高` \| `中` \| `低`                  | Detection confidence. Map English: Confirmed→确认, High→高, Medium→中, Low→低. |
| `location`   | string | No       | `<file_path>:<line> <function>`                 | Human-readable location string. |
| `file_path`  | string | No       | File path                                       | Relative path to the vulnerable file. |
| `line_start` | integer| No       | Positive integer                                | Starting line number of the vulnerable code. |
| `line_end`   | integer| No       | Positive integer ≥ `line_start`                 | Ending line number of the vulnerable code. |
| `function_name` | string | No    | Function/method name                            | Name of the function containing the vulnerability. |

**Severity mapping reference:**

| Report Language (EN)     | Report Language (CN)        | Normalized Value |
| ------------------------ | --------------------------- | ---------------- |
| Critical / P0            | 致命 / 紧急                  | `致命`           |
| High / P1                | 高危 / 严重 / 高             | `严重`           |
| Medium / P2              | 中危 / 中等 / 一般           | `一般`           |
| Low / Info / P3 / P4     | 低危 / 低 / 提示 / 信息      | `提示`           |

---

## 漏洞描述 (Vulnerability Description)

| Field                   | Type   | Required | Description |
| ----------------------- | ------ | -------- | ----------- |
| `vulnerability_title`   | string | **Yes**  | Short, descriptive title. Use the heading from the report. |
| `vulnerability_essence` | string | No       | One-sentence summary of *what* the vulnerability is at its core. |
| `root_cause`            | string | No       | Why the vulnerability exists — the underlying programming error or design flaw. |
| `security_impact`       | string | No       | What an attacker could achieve by exploiting this vulnerability. |

**Extraction hints:**
- `vulnerability_title` is typically the sub-heading for each finding.
- `vulnerability_essence` may be labeled 漏洞本质, 概述, or Summary.
- `root_cause` may be labeled 根因, 原因分析, Root Cause, or appear in an "Analysis" section.
- `security_impact` may be labeled 安全影响, 危害, Impact, or Risk.

---

## 漏洞代码 (Vulnerable Code)

| Field             | Type   | Required | Description |
| ----------------- | ------ | -------- | ----------- |
| `vulnerable_code` | string | No       | The code snippet exhibiting the vulnerability, preserved verbatim with original formatting. |

**Extraction hints:**
- Usually found in a fenced code block (` ``` `) near the vulnerability description.
- Preserve the language tag if present (e.g. `python`, `java`).
- If multiple code blocks exist, use the one closest to the vulnerability heading or explicitly labeled as "vulnerable code" / "漏洞代码".

---

## 数据流路径 (Data Flow Path)

| Field                    | Type          | Required | Description |
| ------------------------ | ------------- | -------- | ----------- |
| `dataflow_source`        | string        | No       | The taint source — where untrusted data enters (e.g. HTTP parameter, file input). |
| `dataflow_propagation`   | array[string] | No       | Ordered list of propagation steps from source to sink. Each element is a code expression or description of a step. |
| `dataflow_sink`          | string        | No       | The dangerous function call where tainted data is consumed (e.g. `cursor.execute()`, `eval()`). |
| `dataflow_sanitization`  | string        | No       | Description of any sanitization or validation applied (or lack thereof). |
| `dataflow_conclusion`    | string        | No       | Summary conclusion of the taint analysis. |

**Extraction hints:**
- Look for sections labeled 数据流分析, Taint Analysis, Data Flow, Source-Sink, 污点分析.
- `dataflow_propagation` is serialized as a JSON array of strings, one per step.

---

## 利用场景 (Exploit Scenario)

| Field           | Type   | Required | Description |
| --------------- | ------ | -------- | ----------- |
| `exploit_steps` | string | No       | Step-by-step attack description. May be a numbered list or narrative. |
| `exploit_poc`   | string | No       | Proof-of-concept code or command. |

**Extraction hints:**
- Look for sections labeled 利用方式, 攻击步骤, Exploitation, PoC, Proof of Concept.
- Preserve code blocks in `exploit_poc`.

---

## 影响 (Impact)

| Field                    | Type   | Required | Allowed Values         | Description |
| ------------------------ | ------ | -------- | ---------------------- | ----------- |
| `impact_confidentiality` | string | No       | `高` \| `中` \| `低`   | Effect on data confidentiality. |
| `impact_integrity`       | string | No       | `高` \| `中` \| `低`   | Effect on data integrity. |
| `impact_availability`    | string | No       | `高` \| `中` \| `低`   | Effect on system availability. |

**Mapping from English:** High→高, Medium→中, Low→低.

---

## 修复建议 (Fix Suggestions)

| Field              | Type   | Required | Description |
| ------------------ | ------ | -------- | ----------- |
| `fix_description`  | string | No       | Narrative explanation of how to fix the vulnerability. |
| `fix_code_before`  | string | No       | The vulnerable code snippet (before fix). |
| `fix_code_after`   | string | No       | The secure code snippet (after fix). |

**Extraction hints:**
- Look for sections labeled 修复建议, 修复方案, Remediation, Fix, Recommendation.
- Before/after code blocks are often presented side by side or sequentially.

---

## 人工确认 (Manual Confirmation)

| Field                        | Type   | Required | Allowed Values / Format                                  | Description |
| ---------------------------- | ------ | -------- | -------------------------------------------------------- | ----------- |
| `manual_confirmation`        | string | No       | Free-form text                                           | Human confirmation notes. |
| `manual_confirmation_status` | string | No       | `待确认` \| `已确认` \| `误报` \| `已修复`                | Confirmation status. Default: `待确认`. |
| `manual_confirmation_notes`  | string | No       | Free-form text                                           | Additional notes from the confirmer. |
| `confirmed_by`               | string | No       | User ID / name                                           | Person who confirmed. |
| `confirmed_at`               | string | No       | ISO-8601 datetime                                        | When confirmation occurred. |

**Defaults:**
- If the report does not include confirmation data, set `manual_confirmation_status` to `待确认` and leave all other confirmation fields as `null`.

---

## 元数据 (Metadata)

| Field        | Type   | Required | Allowed Values / Format                                    | Description |
| ------------ | ------ | -------- | ---------------------------------------------------------- | ----------- |
| `status`     | string | No       | `new` \| `analyzing` \| `resolved` \| `false_positive`     | Current handling status. Default: `new`. |
| `created_at` | string | **Yes**  | ISO-8601 datetime, e.g. `2025-01-15T10:30:00+08:00`       | When this vulnerability record was created. Use report date or current time. |
| `updated_at` | string | No       | ISO-8601 datetime                                          | When this record was last updated. Defaults to `created_at`. |

---

## JSON Schema (for validation)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["report_name", "total_vulnerabilities", "vulnerabilities"],
  "properties": {
    "report_name": { "type": "string" },
    "report_date": { "type": "string", "format": "date-time" },
    "total_vulnerabilities": { "type": "integer", "minimum": 0 },
    "severity_summary": {
      "type": "object",
      "properties": {
        "致命": { "type": "integer" },
        "严重": { "type": "integer" },
        "一般": { "type": "integer" },
        "提示": { "type": "integer" }
      }
    },
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["vuln_id", "task_id", "severity", "vulnerability_title", "created_at"],
        "properties": {
          "vuln_id":                    { "type": "string" },
          "task_id":                    { "type": "string" },
          "severity":                   { "type": "string", "enum": ["致命", "严重", "一般", "提示"] },
          "cvss_score":                 { "type": ["number", "null"] },
          "cvss_vector":                { "type": ["string", "null"] },
          "cwe":                        { "type": ["string", "null"] },
          "confidence":                 { "type": ["string", "null"], "enum": ["确认", "高", "中", "低", null] },
          "location":                   { "type": ["string", "null"] },
          "file_path":                  { "type": ["string", "null"] },
          "line_start":                 { "type": ["integer", "null"] },
          "line_end":                   { "type": ["integer", "null"] },
          "function_name":              { "type": ["string", "null"] },
          "vulnerability_title":        { "type": "string" },
          "vulnerability_essence":      { "type": ["string", "null"] },
          "root_cause":                 { "type": ["string", "null"] },
          "security_impact":            { "type": ["string", "null"] },
          "vulnerable_code":            { "type": ["string", "null"] },
          "dataflow_source":            { "type": ["string", "null"] },
          "dataflow_propagation":       { "type": ["array", "null"], "items": { "type": "string" } },
          "dataflow_sink":              { "type": ["string", "null"] },
          "dataflow_sanitization":      { "type": ["string", "null"] },
          "dataflow_conclusion":        { "type": ["string", "null"] },
          "exploit_steps":              { "type": ["string", "null"] },
          "exploit_poc":                { "type": ["string", "null"] },
          "impact_confidentiality":     { "type": ["string", "null"], "enum": ["高", "中", "低", null] },
          "impact_integrity":           { "type": ["string", "null"], "enum": ["高", "中", "低", null] },
          "impact_availability":        { "type": ["string", "null"], "enum": ["高", "中", "低", null] },
          "fix_description":            { "type": ["string", "null"] },
          "fix_code_before":            { "type": ["string", "null"] },
          "fix_code_after":             { "type": ["string", "null"] },
          "manual_confirmation":        { "type": ["string", "null"] },
          "manual_confirmation_status": { "type": ["string", "null"], "enum": ["待确认", "已确认", "误报", "已修复", null] },
          "manual_confirmation_notes":  { "type": ["string", "null"] },
          "confirmed_by":               { "type": ["string", "null"] },
          "confirmed_at":               { "type": ["string", "null"], "format": "date-time" },
          "status":                     { "type": ["string", "null"], "enum": ["new", "analyzing", "resolved", "false_positive", null] },
          "created_at":                 { "type": "string", "format": "date-time" },
          "updated_at":                 { "type": ["string", "null"], "format": "date-time" }
        }
      }
    }
  }
}
```
