---
name: go-security-audit
description: Comprehensive Go code security audit skill. Performs deep vulnerability analysis on Go projects including project background analysis, audit strategy design, vulnerability pattern matching, taint analysis with data flow tracking, false positive verification, vulnerability classification and rating, attack chain combination analysis, and detailed report generation. Use this skill whenever the user wants to audit Go code for security issues, find vulnerabilities in Go projects, perform Go security review, or analyze Go application security posture — even if they don't explicitly say "audit".
---

# Go Security Audit

A systematic, multi-phase security audit skill for Go codebases. This skill performs deep vulnerability analysis by combining project context understanding, pattern-based detection, data flow tracking, and attack chain analysis to produce actionable security findings with low false-positive rates.

## Workflow Overview

The audit proceeds through 8 phases in sequence. Each phase builds on the outputs of prior phases.

```
Phase 1: Project Background Analysis
    ↓
Phase 2: Mode Selection
    ↓
Phase 3: Audit Strategy Design
    ↓
Phase 4: Tool Execution (only if tool-integration mode)
    ↓
Phase 5: LLM Code Audit (vulnerability discovery → data flow tracking → false positive verification)
    ↓
Phase 6: Vulnerability Classification & Rating
    ↓
Phase 7: Attack Chain Combination Analysis
    ↓
Phase 8: Audit Report Generation
```

---

## Phase 1: Project Background Analysis

Before auditing any code, build a thorough understanding of the project. This context directly shapes the audit strategy in Phase 3.

### 1.1 Identify Project Type

Determine what kind of Go project this is:

- **Web application / API service** (gin, echo, fiber, chi, net/http, gRPC)
- **CLI tool** (cobra, urfave/cli)
- **Microservice** (go-micro, go-kit, kratos)
- **Blockchain / Smart contract** (cosmos-sdk, go-ethereum)
- **Infrastructure / DevOps tool** (Kubernetes operator, Terraform provider)
- **Library / SDK**
- **Other** (describe)

### 1.2 Analyze Technology Stack

Scan the project to identify:

- **Go version** — check `go.mod`
- **Web framework** — gin, echo, fiber, chi, standard net/http, gRPC, etc.
- **Database layer** — database/sql, gorm, ent, sqlx, sqlc, mongo-driver, etc.
- **Authentication** — JWT (golang-jwt), OAuth2, session-based, API keys
- **Serialization** — encoding/json, encoding/xml, protobuf, msgpack
- **Template engine** — html/template, text/template, third-party
- **External integrations** — cloud SDKs, message queues, Redis, etc.
- **Cryptography** — crypto/\*, x/crypto, third-party crypto libs
- **Dependency management** — go.mod dependencies, particularly known-vulnerable versions

### 1.3 Map Key Modules and Business Logic

Identify architectural boundaries and trust zones:

- **Entry points** — HTTP handlers, gRPC methods, CLI commands, message consumers
- **Authentication & authorization modules**
- **Data access layer** — where queries are built and executed
- **File handling** — upload, download, path construction
- **External communication** — outgoing HTTP, DNS, SMTP, command execution
- **Sensitive data processing** — PII, credentials, financial data, health data
- **Configuration management** — env vars, config files, secrets handling
- **Middleware chain** — CORS, rate limiting, logging, auth middleware

Output a structured summary of the project background for use in later phases.

---

## Phase 2: Mode Selection

Two dimensions of configuration control the audit behavior. Apply defaults unless the user explicitly specifies otherwise.

### Audit Mode

| Mode | Description | Default |
|------|-------------|---------|
| **Quick Scan** | Focuses on high-severity patterns (injection, auth bypass, RCE). Skips deep data flow tracking. Suitable for fast feedback. | |
| **Deep Audit** | Full multi-pass analysis including taint tracking, false positive verification, and attack chain analysis. | ✅ Default |

### Audit Method

| Method | Description | Default |
|--------|-------------|---------|
| **Tool Integration** | Run external static analysis tools (gosec, staticcheck, semgrep) first, then use LLM for deeper analysis and false positive triage. | |
| **Pure LLM Audit** | Rely entirely on LLM-based code review with pattern matching, data flow analysis, and reasoning. No external tools required. | ✅ Default |

The default combination is **Deep Audit + Pure LLM Audit**. If the user requests a different combination, adjust accordingly.

---

## Phase 3: Audit Strategy Design

Based on Phase 1 (project context) and Phase 2 (mode selection), design a targeted audit strategy.

### 3.1 Determine Audit Priorities

Map project characteristics to vulnerability categories. The strategy must reflect the actual technology stack and business domain — generic checklists are insufficient.

**Priority mapping examples:**

| Project Characteristic | High-Priority Vulnerability Categories |
|---|---|
| Web API with user input | SQL injection, XSS, SSRF, path traversal, IDOR |
| gRPC service | Protobuf deserialization, auth interceptor bypass, metadata injection |
| File processing service | Path traversal, zip slip, symlink attacks, resource exhaustion |
| Auth module | JWT validation flaws, timing attacks, privilege escalation, session fixation |
| Crypto usage | Weak algorithms, hardcoded keys, IV reuse, improper random generation |
| K8s operator | RBAC misconfiguration, privilege escalation, secret exposure |
| CLI tool with exec | Command injection, argument injection, environment variable injection |

### 3.2 Define Scope and Coverage

Specify:

1. **Critical paths** — the code paths that handle sensitive operations (auth, payments, data access)
2. **Trust boundaries** — where untrusted input enters and where it reaches sensitive sinks
3. **Exclusions** — generated code, vendored dependencies (unless explicitly requested), test files
4. **Depth** — for Quick Scan, limit to entry-point handlers and direct callees; for Deep Audit, trace full call chains

### 3.3 Design File Review Order

Prioritize files that sit on trust boundaries:

1. HTTP/gRPC handlers and route definitions
2. Middleware (auth, validation, sanitization)
3. Database query builders and data access objects
4. File I/O and command execution logic
5. Cryptographic operations
6. Configuration and secret management
7. Utility and helper functions used by the above

Output a written audit plan before proceeding to the next phase.

---

## Phase 4: Tool Execution (Tool Integration Mode Only)

Skip this phase entirely if the audit method is Pure LLM Audit.

When tool integration is selected, run external tools and collect their findings as supplementary input for Phase 5.

### 4.1 Available Tools

| Tool | Purpose | Install Command |
|------|---------|----------------|
| **gosec** | Go-specific security linter | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| **staticcheck** | Advanced Go static analysis | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| **semgrep** | Pattern-based multi-language scanner | `pip install semgrep` or `brew install semgrep` |
| **govulncheck** | Known vulnerability checker for Go deps | `go install golang.org/x/vuln/cmd/govulncheck@latest` |

### 4.2 Execution

Run each available tool and capture output:

```bash
# gosec — security-specific patterns
gosec -fmt json -out gosec-results.json ./...

# staticcheck — broader static analysis
staticcheck -f json ./... > staticcheck-results.json

# govulncheck — known CVEs in dependencies
govulncheck -json ./... > govulncheck-results.json

# semgrep — custom and community Go rules
semgrep --config "p/golang" --json -o semgrep-results.json .
```

### 4.3 Result Normalization

Normalize tool outputs into a unified finding format for Phase 5 input:

```
Finding:
  tool: <tool name>
  rule_id: <rule identifier>
  severity: <high|medium|low>
  file: <file path>
  line: <line number>
  message: <description>
  code_snippet: <relevant code>
```

Tool findings feed into Phase 5 as candidate vulnerabilities that the LLM audit will verify, enrich, or dismiss.

---

## Phase 5: LLM Code Audit

This is the core analysis phase. It proceeds in three stages: vulnerability discovery, data flow tracking, and false positive verification.

### 5.1 Load Vulnerability Pattern Library

Before starting code review, load the vulnerability pattern library from [references/vulnerability-patterns.md](./references/vulnerability-patterns.md).

This library contains Go-specific vulnerability patterns organized by category, each with:
- Pattern description and risk level
- Vulnerable code signatures (what to look for)
- Sink functions and dangerous APIs
- Common source-to-sink flows
- Remediation guidance

### 5.2 Vulnerability Discovery

Systematically review code files in the order defined by the audit plan (Phase 3). For each file:

1. **Pattern matching** — compare code against the vulnerability pattern library. Look for:
   - Direct use of dangerous APIs (e.g., `fmt.Sprintf` in SQL queries, `os/exec` with user input)
   - Missing input validation at trust boundaries
   - Insecure default configurations
   - Error handling that leaks sensitive information
   - Race conditions in concurrent code
   - Improper use of cryptographic primitives

2. **Semantic analysis** — go beyond pattern matching to understand code intent:
   - Is this input validation actually effective, or can it be bypassed?
   - Does this authorization check cover all relevant paths?
   - Are there implicit assumptions about data format or trust level?

3. **Record each finding** with:
   - Vulnerability type (from pattern library category)
   - Location (file, function, line range)
   - Sink point (the dangerous operation)
   - Suspected source (where untrusted data originates)
   - Preliminary severity assessment
   - Code snippet showing the issue

For **Quick Scan mode**, stop here and proceed to Phase 6 (skip 5.3 and 5.4).

For **Deep Audit mode**, continue with data flow tracking and false positive verification.

### 5.3 Data Flow Tracking (Taint Analysis)

For each vulnerability found in 5.2, trace the data flow from source to sink to confirm exploitability.

#### Step 1: Identify the Sink's Enclosing Function

Starting from the sink point (the vulnerable operation), identify the function that directly contains it.

#### Step 2: Build the Call Chain

From the enclosing function, trace callers upward:

1. Search the codebase for all call sites of the enclosing function
2. For each caller, determine whether it passes user-controllable data to the parameter that reaches the sink
3. Continue tracing upward until you reach an entry point (HTTP handler, gRPC method, CLI argument parser, etc.) or determine the data is not user-controllable

Build a call chain like:

```
[Entry Point] handler.CreateUser()
    → [Business Logic] service.ProcessUser(input)
        → [Data Access] repo.SaveUser(query)
            → [Sink] db.Exec(query)  ← SQL injection sink
```

#### Step 3: Taint Propagation Analysis

Along each call chain, track how the tainted data transforms:

- **Propagators** — functions that pass taint through (e.g., `strings.TrimSpace`, `fmt.Sprintf`, struct field assignment)
- **Sanitizers** — functions that neutralize taint (e.g., parameterized queries, `html.EscapeString`, allowlist validation)
- **Conditional taint** — branches where taint may or may not flow depending on runtime conditions

Record the complete data flow path:

```
Source: r.FormValue("username")  [HTTP request parameter]
  → assigned to `input.Name`    [struct field propagation]
  → passed to service.Process() [function argument propagation]
  → concatenated into SQL via fmt.Sprintf()  [string propagation - NO sanitization]
  → db.Exec(query)              [SINK: SQL execution]
```

### 5.4 False Positive Verification

For each vulnerability with a traced data flow, perform verification to eliminate false positives.

#### Verification Checks

1. **Sanitization check** — Is there any validation or sanitization between source and sink?
   - Input validation (regex, allowlist, type assertion)
   - Parameterized queries or prepared statements
   - Output encoding (HTML, URL, SQL escaping)
   - Framework-level protections (e.g., ORM auto-escaping)

2. **Reachability check** — Can the vulnerable path actually be reached?
   - Is the endpoint publicly accessible or behind authentication?
   - Are there middleware guards (rate limiting, WAF, input size limits)?
   - Is the function dead code or only called in test contexts?

3. **Exploitability assessment** — Even if reachable, is exploitation practical?
   - Does the data format constrain the attack payload?
   - Are there additional runtime protections (CSP headers, database permissions)?
   - Would exploitation require chaining with another vulnerability?

#### Verdict for Each Finding

After verification, assign a confidence level:

- **Confirmed** — clear source-to-sink path with no effective sanitization; exploitable
- **Likely** — path exists but exploitation depends on specific runtime conditions
- **Suspicious** — potential issue but significant mitigating factors exist
- **False Positive** — effective sanitization found, path unreachable, or non-exploitable; dismiss with explanation

Remove false positives from the final findings list. Retain "Suspicious" findings with a note about the uncertainty.

---

## Phase 6: Vulnerability Classification & Rating

Classify and rate each confirmed or likely vulnerability.

### 6.1 Classification

Assign each vulnerability to a CWE category:

| Category | Common CWE IDs |
|---|---|
| Injection | CWE-89 (SQL), CWE-78 (OS Command), CWE-79 (XSS), CWE-917 (Expression Language) |
| Broken Authentication | CWE-287, CWE-384, CWE-613 |
| Sensitive Data Exposure | CWE-200, CWE-312, CWE-319 |
| Broken Access Control | CWE-862, CWE-863, CWE-639 |
| Security Misconfiguration | CWE-16, CWE-1188 |
| Cryptographic Failures | CWE-326, CWE-327, CWE-330 |
| SSRF | CWE-918 |
| Path Traversal | CWE-22 |
| Race Condition | CWE-362 |
| Deserialization | CWE-502 |

### 6.2 Severity Rating (CVSS-aligned)

Rate each vulnerability considering:

| Factor | Assessment Criteria |
|---|---|
| **Attack Vector** | Network / Adjacent / Local / Physical |
| **Attack Complexity** | Low (trivially exploitable) / High (requires specific conditions) |
| **Privileges Required** | None / Low / High |
| **User Interaction** | None / Required |
| **Impact: Confidentiality** | None / Low / High |
| **Impact: Integrity** | None / Low / High |
| **Impact: Availability** | None / Low / High |

Assign a severity label:

| Severity | CVSS Score Range | Description |
|---|---|---|
| **Critical** | 9.0 – 10.0 | Remote exploitation, no auth required, high impact |
| **High** | 7.0 – 8.9 | Significant impact, moderate exploitation difficulty |
| **Medium** | 4.0 – 6.9 | Limited impact or higher exploitation difficulty |
| **Low** | 0.1 – 3.9 | Minimal impact, difficult to exploit |
| **Informational** | 0.0 | Best practice recommendation, no direct security impact |

---

## Phase 7: Attack Chain Combination Analysis

Independent vulnerabilities can sometimes be combined into attack chains with greater overall impact than any single finding. This phase identifies such chains.

### 7.1 Principles

- **Causality required** — each step in the chain must produce a concrete output (data, access, state change) that enables the next step
- **Continuity** — the chain must be executable end-to-end without gaps; if step N's output cannot actually feed into step N+1, the chain is invalid
- **No speculation** — do not fabricate connections between unrelated vulnerabilities; every link must be grounded in the code and data flow evidence from Phase 5
- **Practical exploitation** — the combined attack must represent a realistic scenario, not a theoretical worst-case

### 7.2 Chain Construction Process

1. **Build a vulnerability adjacency map** — for each finding, list what an attacker gains by exploiting it (e.g., "read arbitrary files", "bypass auth for endpoint X", "execute SQL queries as db user Y")
2. **Identify chain candidates** — look for pairs where one vulnerability's output enables another vulnerability's precondition:
   - Information disclosure → enables targeted injection (e.g., leaked DB schema enables SQL injection)
   - Auth bypass → enables access to endpoints with other vulnerabilities
   - SSRF → enables access to internal services with weaker security
   - Path traversal → enables reading config/secrets → enables privilege escalation
3. **Validate each chain** — walk through the chain step-by-step, confirming that each transition is supported by actual code paths and data flows
4. **Rate the combined impact** — the chain's severity is based on the final impact achievable, not the individual vulnerability severities

### 7.3 Output Format

For each valid attack chain:

```
Attack Chain: [descriptive name]
Combined Severity: [Critical/High/Medium]
Steps:
  1. [Vulnerability A] → attacker gains [specific capability]
  2. [Vulnerability B] (enabled by step 1) → attacker gains [escalated capability]
  3. ...
Final Impact: [what the attacker ultimately achieves]
Preconditions: [what the attacker needs before step 1]
```

If no valid attack chains are found, explicitly state this — do not force combinations that don't hold up.

---

## Phase 8: Audit Report Generation

Generate a comprehensive security audit report. Load the report template from [references/report-template.md](./references/report-template.md).

### Report Structure

The report must include:

1. **Executive Summary** — high-level findings, overall risk posture, key numbers (critical/high/medium/low counts)
2. **Project Overview** — project background from Phase 1 (type, stack, architecture)
3. **Audit Scope & Methodology** — what was audited, mode and method used, tools run (if any), files and modules covered
4. **Findings Summary Table** — all findings sorted by severity, with ID, title, severity, CWE, location
5. **Detailed Findings** — for each vulnerability:
   - Title and ID
   - Severity and CWE classification
   - Location (file, function, line range)
   - Description of the vulnerability
   - Data flow path (source → propagation → sink) from Phase 5.3
   - Proof of concept or exploitation scenario
   - Remediation recommendation with code example
6. **Attack Chain Analysis** — from Phase 7, if any chains were identified
7. **Remediation Priority Matrix** — ordered list of fixes by impact-to-effort ratio
8. **Appendices**
   - Tool scan results (if tool integration was used)
   - Full list of files reviewed
   - False positives dismissed (with reasoning)
   - Methodology notes

### Report Quality Requirements

- Every finding must include a concrete remediation with a Go code example showing the fix
- Severity ratings must be justified, not just assigned
- Data flow paths must be specific (file names, function names, line references), not abstract
- The report should be actionable — a developer should be able to fix each issue using only the report

---

## Reference Files

Load these resources as needed during the audit:

- [Vulnerability Pattern Library](./references/vulnerability-patterns.md) — Go-specific vulnerability patterns organized by category. Load at the beginning of Phase 5.1. Contains sink functions, dangerous APIs, vulnerable code signatures, and remediation patterns for all major Go vulnerability categories.

- [Audit Strategy Templates](./references/audit-strategy-templates.md) — Pre-built audit strategy templates for common Go project types. Load during Phase 3 to accelerate strategy design. Contains priority matrices and scope definitions for web APIs, microservices, CLI tools, and more.

- [Report Template](./references/report-template.md) — The structural template for the final audit report. Load at the beginning of Phase 8. Contains section headers, formatting guidelines, and example content for each report section.
