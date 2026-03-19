# Audit Report Template

Use this template to structure the final security audit report in Phase 8. Fill in each section with findings from the preceding phases.

---

## Report Header

```
# Security Audit Report: [Project Name]

**Audit Date:** [Date]
**Auditor:** Claude (AI-assisted code audit)
**Audit Mode:** [Quick Scan / Deep Audit]
**Audit Method:** [Pure LLM Audit / Tool Integration + LLM Audit]
**Report Version:** 1.0
```

---

## Section 1: Executive Summary

Provide a concise overview aimed at technical leadership and security stakeholders.

```markdown
## 1. Executive Summary

### Overall Risk Assessment: [Critical / High / Medium / Low]

This security audit of [project name] identified **[total count]** security findings:

| Severity | Count |
|----------|-------|
| Critical | [N]   |
| High     | [N]   |
| Medium   | [N]   |
| Low      | [N]   |
| Info     | [N]   |

### Key Findings

1. **[Most critical finding title]** — [one-sentence description and impact]
2. **[Second most critical finding]** — [one-sentence description and impact]
3. **[Third most critical finding]** — [one-sentence description and impact]

### Attack Chains Identified

[N] attack chains were identified that combine multiple vulnerabilities for greater impact.
The most severe chain: [brief description of the highest-impact chain].

### Top Recommendations

1. [Highest priority fix — what to do and why]
2. [Second priority fix]
3. [Third priority fix]
```

---

## Section 2: Project Overview

Summarize the project background analysis from Phase 1.

```markdown
## 2. Project Overview

### Project Type
[e.g., REST API service, gRPC microservice, CLI tool]

### Technology Stack

| Component | Technology |
|-----------|-----------|
| Language  | Go [version] |
| Framework | [gin/echo/chi/...] |
| Database  | [postgres/mysql/...] via [gorm/sqlx/...] |
| Auth      | [JWT/OAuth2/session/...] |
| Other     | [notable dependencies] |

### Architecture Overview
[Brief description of the project architecture, key modules, trust boundaries]

### Key Modules

| Module | Description | Security Relevance |
|--------|-------------|-------------------|
| [module name] | [what it does] | [why it matters for security] |
| ... | ... | ... |
```

---

## Section 3: Audit Scope & Methodology

Document what was audited and how.

```markdown
## 3. Audit Scope & Methodology

### Scope

**Included:**
- [List of directories/modules/files audited]
- [Specific functionality areas covered]

**Excluded:**
- [Generated code, vendored dependencies, test files, etc.]
- [Reason for each exclusion]

### Methodology

**Mode:** [Deep Audit / Quick Scan]
**Method:** [Pure LLM Audit / Tool Integration + LLM Audit]

**Audit phases executed:**
1. Project background analysis
2. Audit strategy design based on [project type] profile
3. [If tool integration] Tool scanning with [gosec, staticcheck, govulncheck, semgrep]
4. LLM-based vulnerability discovery using Go vulnerability pattern library
5. [If deep audit] Data flow tracking and taint analysis for each finding
6. [If deep audit] False positive verification
7. Vulnerability classification and CVSS-aligned severity rating
8. [If deep audit] Attack chain combination analysis

### Files Reviewed

[Total files reviewed: N]

| Category | Files | Examples |
|----------|-------|---------|
| Handlers/Controllers | [N] | [file list] |
| Middleware | [N] | [file list] |
| Data Access | [N] | [file list] |
| Business Logic | [N] | [file list] |
| Configuration | [N] | [file list] |
| Other | [N] | [file list] |
```

---

## Section 4: Findings Summary

A sortable overview table of all findings.

```markdown
## 4. Findings Summary

| ID | Title | Severity | CWE | Location | Confidence |
|----|-------|----------|-----|----------|------------|
| VULN-001 | [title] | Critical | CWE-89 | `pkg/handler/user.go:45` | Confirmed |
| VULN-002 | [title] | High | CWE-287 | `pkg/auth/jwt.go:23` | Confirmed |
| VULN-003 | [title] | Medium | CWE-200 | `pkg/middleware/error.go:12` | Likely |
| ... | ... | ... | ... | ... | ... |

### Severity Distribution

- **Critical:** [N] findings requiring immediate remediation
- **High:** [N] findings requiring prompt attention
- **Medium:** [N] findings to address in the near term
- **Low:** [N] findings to address when feasible
- **Informational:** [N] best practice recommendations
```

---

## Section 5: Detailed Findings

For each vulnerability, provide the full analysis. Repeat this block for every finding.

```markdown
## 5. Detailed Findings

---

### VULN-[ID]: [Descriptive Title]

**Severity:** [Critical / High / Medium / Low / Info]
**CVSS Score:** [X.X] ([vector string if applicable])
**CWE:** CWE-[ID] — [CWE Name]
**Confidence:** [Confirmed / Likely / Suspicious]
**Location:** `[file]:[line range]` in function `[function name]`

#### Description

[Clear explanation of the vulnerability. What is the issue, what makes it exploitable,
and what is the security impact.]

#### Vulnerable Code

```go
// file: [filepath]
// lines: [start]-[end]
[paste the vulnerable code snippet]
```

#### Data Flow Path

[For Deep Audit mode — show the traced source-to-sink path]

```
Source: [where untrusted data enters]
  → [propagation step 1 — file:function]
  → [propagation step 2 — file:function]
  → [sanitization check: NONE FOUND / found but insufficient because...]
  → Sink: [dangerous operation — file:function:line]
```

#### Exploitation Scenario

[Step-by-step description of how an attacker could exploit this vulnerability.
Include a concrete example — a sample HTTP request, CLI input, or gRPC call.]

```
Example attack:
  [curl command, gRPC call, or code snippet demonstrating exploitation]
```

#### Impact

- **Confidentiality:** [None / Low / High — explain]
- **Integrity:** [None / Low / High — explain]
- **Availability:** [None / Low / High — explain]

#### Remediation

[Specific, actionable fix with Go code example]

**Recommended fix:**

```go
// file: [filepath]
// Replace vulnerable code with:
[corrected code snippet]
```

**Additional hardening:**
- [Any defense-in-depth measures]

---
```

---

## Section 6: Attack Chain Analysis

Present attack chains identified in Phase 7.

```markdown
## 6. Attack Chain Analysis

### Chain 1: [Descriptive Name]

**Combined Severity:** [Critical / High / Medium]
**Vulnerabilities involved:** VULN-[ID1], VULN-[ID2], VULN-[ID3]

**Attack narrative:**

| Step | Vulnerability | Action | Attacker Gains |
|------|--------------|--------|---------------|
| 1 | VULN-[ID1]: [title] | [what the attacker does] | [what capability they gain] |
| 2 | VULN-[ID2]: [title] | [using output of step 1, attacker does...] | [escalated capability] |
| 3 | VULN-[ID3]: [title] | [using output of step 2, attacker does...] | [final impact] |

**Preconditions:** [What the attacker needs before starting — e.g., network access, valid low-privilege account]

**Final Impact:** [Ultimate consequence — e.g., full database access, RCE as service account, complete account takeover]

**Chain Validation:** [Confirm that each step's output concretely enables the next step. Reference specific code paths and data flows.]

---

[Repeat for additional chains]

### No Attack Chains Identified

[If no valid chains were found, state this explicitly:]

No attack chains were identified. The discovered vulnerabilities are independent and
do not enable meaningful chained exploitation beyond their individual impact.
```

---

## Section 7: Remediation Priority Matrix

Order fixes by impact-to-effort ratio to guide development planning.

```markdown
## 7. Remediation Priority Matrix

| Priority | Finding ID | Title | Severity | Estimated Effort | Rationale |
|----------|-----------|-------|----------|-----------------|-----------|
| 1 | VULN-[ID] | [title] | Critical | Low | [Simple fix, high impact — e.g., add parameterized queries] |
| 2 | VULN-[ID] | [title] | Critical | Medium | [Requires refactoring auth middleware] |
| 3 | VULN-[ID] | [title] | High | Low | [Add input validation — quick win] |
| 4 | VULN-[ID] | [title] | High | High | [Architectural change needed for proper access control] |
| ... | ... | ... | ... | ... | ... |

### Remediation Categories

**Immediate (address before next deployment):**
- [List of critical findings that should block deployment]

**Short-term (address within current sprint/cycle):**
- [List of high findings]

**Medium-term (plan for upcoming work):**
- [List of medium findings and architectural improvements]

**Long-term (technical debt / hardening):**
- [List of low/info findings and defense-in-depth measures]
```

---

## Section 8: Appendices

```markdown
## 8. Appendices

### A. Tool Scan Results

[If tool integration mode was used, include summarized tool outputs]

**gosec:** [N] findings ([N] high, [N] medium, [N] low)
**staticcheck:** [N] findings
**govulncheck:** [N] known vulnerabilities in dependencies
**semgrep:** [N] findings

[Include notable tool findings or reference attached JSON files]

### B. Full File List

[Complete list of all files reviewed during the audit]

### C. Dismissed False Positives

| Finding | Location | Reason Dismissed |
|---------|----------|-----------------|
| [description] | `file:line` | [Effective sanitization found at file:line — parameterized query] |
| [description] | `file:line` | [Path unreachable — endpoint requires admin auth and internal network] |
| ... | ... | ... |

### D. Methodology Notes

- Vulnerability pattern library version: [date/version]
- Audit strategy template used: [template name]
- [Any deviations from standard methodology and reason]
- [Limitations of the audit — areas not covered and why]
```

---

## Formatting Guidelines

1. **Severity colors** — if rendering in Markdown with HTML support, use color indicators:
   - Critical: red
   - High: orange
   - Medium: yellow
   - Low: blue
   - Info: gray

2. **Code snippets** — always include file path and line numbers for traceability

3. **Data flow paths** — use arrow notation (`→`) consistently, one step per line

4. **Findings IDs** — use sequential `VULN-001`, `VULN-002` format

5. **Remediation code** — show both the "before" (vulnerable) and "after" (fixed) code

6. **Attack chains** — use numbered steps with clear transitions; each step must reference the specific vulnerability ID

7. **Report length** — be thorough but not verbose. Each finding should be self-contained so a developer can read just their assigned finding and have everything needed to fix it.
