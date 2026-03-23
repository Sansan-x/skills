---
name: 5gc-context-aware
description: 5G Core Network business-aware code audit skill. Generates a "5GC Business Panorama" for security auditing of Go-based 5GC network functions (AMF, SMF, UPF, AUSF, UDM, NRF, PCF, etc.). Identifies the NF type, maps SBI/NGAP/PFCP/NAS interfaces, tags sensitive assets (SUPI, GUTI, K_NAS, TEID), and checks 3GPP TS 33.501 compliance. Produces an Audit Manifest to guide directed taint analysis. Use this skill whenever auditing 5G core network Go code, reviewing 3GPP protocol implementations, assessing telecom security, or analyzing free5gc/open5gs/magma codebases.
---

# 5GC-Context-Aware: Business-Aware Code Audit for 5G Core Network

This skill equips you with a comprehensive "5GC Business Panorama" (5GC 业务全景图), enabling context-aware security auditing of Go-based 5G Core Network implementations. Rather than treating 5GC code as generic Go, this skill understands which signaling messages are being processed, which interfaces are involved, and what security constraints apply according to 3GPP specifications.

## When To Use This Skill

- Auditing Go source code for 5GC Network Functions (AMF, SMF, UPF, AUSF, UDM, UDR, NRF, PCF, NSSF, NEF)
- Security review of 3GPP protocol implementations (NGAP, NAS-5G, PFCP, GTP-U, SBI/HTTP2)
- Assessing codebases like free5gc, open5gs, magma, or custom 5GC implementations
- Checking 3GPP TS 33.501 compliance in core network code
- Identifying sensitive subscriber data handling issues (SUPI/IMSI leaks, key exposure)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   go-audit (Caller)                         │
│  Calls 5GC-Context-Aware at startup for project-wide scan  │
└────────────────────────┬────────────────────────────────────┘
                         │ Input: project directory
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               5GC-Context-Aware Skill                       │
│                                                             │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │ Step 1       │  │ Step 2        │  │ Step 3          │  │
│  │ Service      │→ │ Interface     │→ │ Sensitive Asset  │  │
│  │ Profiling    │  │ Mapping       │  │ Tagging         │  │
│  └──────────────┘  └───────────────┘  └─────────────────┘  │
│         │                                      │            │
│         ▼                                      ▼            │
│  ┌──────────────┐           ┌──────────────────────────┐   │
│  │ Step 4       │           │ Attack Pattern           │   │
│  │ Spec         │──────────→│ Correlation              │   │
│  │ Compliance   │           │ (go-vuln-lib/insight)    │   │
│  └──────────────┘           └──────────────────────────┘   │
│                                      │                      │
│                                      ▼                      │
│                        ┌──────────────────────┐             │
│                        │  Audit Manifest      │             │
│                        │  (JSON output)       │             │
│                        └──────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼ Output: audit_manifest.json
┌─────────────────────────────────────────────────────────────┐
│  go-audit: Directed taint analysis using manifest           │
└─────────────────────────────────────────────────────────────┘
```

## Execution Process

Run the full pipeline against a target 5GC Go project:

```bash
python -m scripts.audit_manifest_generator <project_dir> [skill_dir]
```

Or run individual steps for targeted analysis:

```bash
# Step 1: Identify which NF this project is
python scripts/service_profiler.py <project_dir>

# Step 2: Map all interfaces (SBI routes, NGAP/NAS/PFCP handlers)
python scripts/interface_mapper.py <project_dir> [skill_dir] [nf_type]

# Step 3: Tag sensitive variables in the codebase
python scripts/asset_tagger.py <project_dir>

# Step 4: Check 3GPP TS 33.501 compliance
python scripts/spec_compliance.py <project_dir> [skill_dir] [nf_type]
```

All scripts output JSON to stdout (progress to stderr), suitable for piping into downstream tools.

---

## Step 1: Service Profiling (服务画像)

Identifies which Network Function the target project implements. This is foundational — all subsequent steps use the NF type to scope their analysis.

**How it works:**

1. **go.mod analysis**: Matches the module path against known NF patterns (e.g., `free5gc/amf`, `open5gs.*smf`)
2. **Config file scan**: Searches YAML/JSON configs for `nfType` fields and NF-specific configuration keys (e.g., `ngapIpList` for AMF, `pfcpAddr` for SMF/UPF)
3. **Init code scan**: Finds initialization functions (e.g., `AMF.Start()`, `NewSMFApp()`) and key package imports
4. **Weighted scoring**: Combines all signals with confidence weights to determine the most likely NF type

**Supported NF types**: AMF, SMF, UPF, NRF, AUSF, UDM, UDR, PCF, NSSF, NEF

**Reference data**: `references/nf_signatures.json` contains all identification signatures. If auditing a custom NF implementation, you can extend this file with additional patterns.

**Output format:**
```json
{
  "identified_nf": {
    "type": "AMF",
    "full_name": "Access and Mobility Management Function",
    "confidence": 95.2,
    "interfaces": ["N1", "N2", "N8", "N11", "N12", "N14", "N15", "N22"],
    "protocols": ["NGAP", "NAS-5G", "HTTP/2", "SCTP"]
  }
}
```

---

## Step 2: Interface & Protocol Mapping (接口与协议映射)

Builds a complete map of all communication interfaces, essential for understanding the attack surface.

**SBI (Service-Based Interface) route extraction:**
- Detects the HTTP framework (Gin, Echo, Gorilla Mux, net/http)
- Extracts route registrations with method, path, and handler function
- Maps routes to 3GPP-defined SBI APIs (e.g., `/namf-comm/v1/ue-contexts` → TS 29.518)
- Flags security-critical operations that require authorization checks

**Binary protocol handler identification:**
- **NGAP** (N2): ASN.1 APER-encoded messages between AMF and gNB
- **NAS-5G** (N1): UE-to-network signaling encapsulated in NGAP
- **PFCP** (N4): Session management between SMF and UPF
- **GTP-U** (N3/N9): User plane tunnel protocol

**Authentication middleware detection:**
- Identifies auth/token validation middleware in HTTP handler chains
- Flags routes that lack authentication coverage

**Reference data**: `references/interface_specs.json` contains SBI API path definitions, binary protocol procedure catalogs, and HTTP framework detection patterns.

---

## Step 3: Sensitive Asset Tagging (敏感资产标记)

Performs a lightweight AST-aware scan to mark variables, struct fields, and function parameters that handle sensitive 5GC data.

**Asset categories (by sensitivity):**

| Category | Sensitivity | Examples |
|----------|------------|---------|
| Subscriber Identity | Critical | `supi`, `suci`, `imsi`, `guti`, `gpsi`, `pei` |
| Cryptographic Keys | Critical | `kNasEnc`, `kNasInt`, `kAmf`, `kAusf`, `xresStar` |
| Security Context | Critical | `nasSecurityContext`, `nasCount`, `ngKsi` |
| Session Data | High | `teid`, `pduSessionId`, `qfi`, `pdrId`, `ueIpAddr` |
| Location Data | High | `tai`, `cellId`, `nrCgi`, `userLocation` |

**How it works:**
1. Parses Go struct definitions, extracting field names and types
2. Parses function signatures, including receiver types and parameters
3. Parses variable declarations (`var` and `:=`)
4. Matches all identifiers against regex patterns from `references/sensitive_assets.json`
5. Reports "hotspot files" — files with the highest density of sensitive data handling

**Struct type detection**: Recognizes known context structs (`AmfUe`, `SmContext`, `PfcpSession`, etc.) that aggregate sensitive fields. These structs are priority targets for race condition and lifecycle analysis.

---

## Step 4: Spec Compliance Check (规范合规性预检)

Checks the codebase against 3GPP TS 33.501 security requirements, organized by domain.

**Compliance domains checked:**

| Domain | Key Checks | Relevant NFs |
|--------|-----------|-------------|
| Authentication (6.1) | 5G-AKA/EAP-AKA' implementation, SN-Name inclusion, SUPI concealment | AMF, AUSF |
| NAS Security (6.7) | Integrity/cipher after SMC, NIA0 restriction, NAS COUNT replay protection | AMF |
| NGAP Security (9.2) | NDS/IP protection, RAN node validation | AMF |
| SBI Security (13) | mTLS enforcement, OAuth2 token validation, TLS 1.2+ | All NFs |
| PFCP Security (9.3) | Transport security, peer validation, session authorization | SMF, UPF |
| Subscriber Privacy (6.12) | SUCI ECIES enforcement, GUTI refresh, paging privacy | AMF, UDM |
| Key Management (Annex A) | Key hierarchy compliance, FC-based derivation, key erasure | AMF, AUSF, UDM |

**Insecure pattern detection** (runs regardless of NF type):
- `InsecureSkipVerify: true` — disabled TLS verification
- Weak TLS versions (< 1.2)
- Hardcoded credentials
- SUPI/IMSI in log output
- NIA0/NEA0 usage outside initial context
- Unchecked errors on Unmarshal/Decode operations

**Reference data**: `references/3gpp_security_baseline.json` contains all compliance checks with code patterns, fail conditions, and spec section references.

---

## Output: Audit Manifest (审计导航清单)

The final output is `audit_manifest.json`, a structured document containing:

1. **Service Profile**: NF type, interfaces, protocols, confidence score
2. **Interface Map**: All SBI routes and protocol handlers with security annotations
3. **Sensitive Assets**: Tagged variables with hotspot file rankings
4. **Compliance Results**: Check-by-check results with critical gap highlights
5. **Attack Pattern Correlations**: NF-specific vulnerability patterns matched to project context (cross-referenced with `references/attack_patterns.json`)
6. **Taint Analysis Directives**: Specific source/sink pairs for downstream taint engines
7. **Audit Priority Queue**: Ordered list of audit tasks, from critical compliance gaps to entry point reviews

See `examples/sample_manifest.json` for a complete example of AMF audit output.

---

## Reference Files

Read these files for detailed pattern definitions and to extend the skill's knowledge base:

| File | Contents | When to read |
|------|---------|-------------|
| `references/nf_signatures.json` | NF identification patterns (module names, config fields, init functions) | Extending NF detection for custom implementations |
| `references/interface_specs.json` | SBI API paths, binary protocol procedures, router framework patterns | Understanding interface mapping logic |
| `references/sensitive_assets.json` | Sensitive variable patterns by category with regex and spec references | Adding custom sensitive data patterns |
| `references/attack_patterns.json` | Common + NF-specific attack patterns with CWE mappings | Understanding threat model for specific NF |
| `references/3gpp_security_baseline.json` | TS 33.501 compliance checks organized by security domain | Understanding compliance check details |
| `examples/sample_manifest.json` | Example audit manifest output for an AMF project | Understanding output format |

---

## Integration with Other Skills

**Input from go-audit**: The calling audit framework provides the target project directory. On startup, it invokes 5GC-Context-Aware for a full project scan.

**Cross-reference with go-vuln-lib**: Attack patterns in `references/attack_patterns.json` represent the NF-specific vulnerability knowledge base. The correlation engine matches discovered interfaces and assets against these patterns to produce targeted audit directives.

**Enhancement via go-vuln-insight**: Historical vulnerability cases are used to enrich the Audit Manifest with real-world exploitation context. The `attack_pattern_correlations` section maps each pattern to relevant CVE references and exploitation techniques.

**Output to go-audit**: The Audit Manifest's `taint_analysis_directives` and `audit_priority_queue` provide actionable inputs for the taint analysis engine, specifying exact source/sink pairs, entry points, and compliance gaps to investigate.

---

## Extending This Skill

**Adding a new NF type**: Add entries to `nf_signatures.json` with module patterns, config identifiers, init function patterns, and key imports.

**Adding attack patterns**: Add entries to `attack_patterns.json` under `common_patterns` (applies to all NFs) or `nf_specific_patterns.<NF_TYPE>` (applies to one NF).

**Adding compliance checks**: Add checks to `3gpp_security_baseline.json` under the appropriate domain, or create a new domain section.

**Adding sensitive assets**: Add regex patterns to `sensitive_assets.json` under the appropriate category, or create a new category with sensitivity level.

**Custom router frameworks**: Add framework detection patterns to `interface_specs.json` under `router_patterns`.
