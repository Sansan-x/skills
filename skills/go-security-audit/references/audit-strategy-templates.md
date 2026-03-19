# Audit Strategy Templates

Pre-built audit strategy templates for common Go project types. Use these as a starting point in Phase 3 and customize based on the specific project's characteristics identified in Phase 1.

## Table of Contents

1. [Web API / REST Service](#1-web-api--rest-service)
2. [gRPC Microservice](#2-grpc-microservice)
3. [Web Application (Server-Side Rendering)](#3-web-application-server-side-rendering)
4. [CLI Tool](#4-cli-tool)
5. [Kubernetes Operator / Controller](#5-kubernetes-operator--controller)
6. [Blockchain / DeFi Application](#6-blockchain--defi-application)
7. [Library / SDK](#7-library--sdk)
8. [File Processing Service](#8-file-processing-service)
9. [Gateway / Proxy Service](#9-gateway--proxy-service)

---

## 1. Web API / REST Service

**Typical stack:** gin / echo / chi / fiber + GORM / sqlx + JWT / OAuth2

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | SQL Injection | Direct database interaction with user input |
| P0 | Broken Authentication | JWT/session handling flaws grant full access |
| P0 | Broken Access Control / IDOR | API endpoints expose resources by ID |
| P1 | SSRF | APIs often proxy or fetch external resources |
| P1 | Mass Assignment | JSON binding to structs may expose internal fields |
| P1 | Information Disclosure | Error responses may leak internals |
| P2 | Rate Limiting / DoS | APIs are publicly accessible |
| P2 | CORS Misconfiguration | Cross-origin security |
| P2 | Log Injection | Request data logged without sanitization |

### Scope Definition

**Must audit:**
- All route definitions and handler functions
- Authentication middleware and token validation logic
- Authorization checks in every handler (IDOR focus)
- Database query construction in all data access functions
- Request body binding and input validation
- Error handling and response formatting
- CORS configuration
- Rate limiting configuration

**Key file patterns to locate:**
```
**/router.go, **/routes.go, **/handler*.go, **/controller*.go
**/middleware*.go, **/auth*.go
**/model*.go, **/repository*.go, **/dao*.go, **/store*.go
**/service*.go (business logic layer)
**/config*.go, **/main.go
```

### Mass Assignment — Go-Specific Check

In Go REST APIs, `c.BindJSON(&req)` or `json.Decode` maps JSON fields to struct fields. If the struct has fields that should not be user-settable (e.g., `IsAdmin`, `Role`, `ID`), check that either:
- A separate DTO struct is used for input (without sensitive fields)
- Sensitive fields have `json:"-"` tag
- Manual field copying is used instead of full struct binding

**Vulnerable:**
```go
type User struct {
    ID      int    `json:"id"`
    Name    string `json:"name"`
    IsAdmin bool   `json:"is_admin"`  // settable via JSON input
}
func CreateUser(c *gin.Context) {
    var user User
    c.BindJSON(&user)
    db.Create(&user)
}
```

---

## 2. gRPC Microservice

**Typical stack:** gRPC + protobuf + gorm/ent + internal service mesh

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | Auth Interceptor Bypass | Missing or misconfigured auth in interceptors |
| P0 | SQL Injection | Backend database queries |
| P0 | Privilege Escalation | Service-to-service trust assumptions |
| P1 | Metadata Injection | Client-controlled gRPC metadata used for authorization |
| P1 | Protobuf Message Validation | Missing field validation on incoming messages |
| P1 | Insecure Inter-Service Communication | Plaintext gRPC without mTLS |
| P2 | Resource Exhaustion | Large message payloads, streaming abuse |
| P2 | Reflection Enabled in Production | Service discovery exposure |

### Scope Definition

**Must audit:**
- gRPC server initialization and interceptor chain
- All RPC method implementations
- Protobuf message definitions (check for missing validation)
- Metadata extraction and usage in authorization
- TLS / mTLS configuration for inter-service calls
- Database queries within RPC handlers
- Error status codes and messages (information leakage)

**Key file patterns:**
```
**/*.proto (message and service definitions)
**/server.go, **/grpc*.go
**/interceptor*.go, **/middleware*.go
**/service*.go, **/handler*.go
**/repository*.go, **/store*.go
```

### Inter-Service Trust Check

In microservice architectures, services often trust each other implicitly. Verify:
- Does service A validate that requests from service B are legitimate (mutual TLS, signed tokens)?
- If service A calls service B with elevated privileges, can a compromised service B abuse those privileges?
- Are internal-only endpoints actually unreachable from outside the service mesh?

---

## 3. Web Application (Server-Side Rendering)

**Typical stack:** net/http / gin + html/template / text/template + sessions

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | XSS | Server-rendered HTML with user data |
| P0 | SQL Injection | Form data → database queries |
| P0 | CSRF | State-changing forms without CSRF tokens |
| P0 | Session Management Flaws | Cookie-based sessions |
| P1 | Path Traversal | File serving, upload/download |
| P1 | Open Redirect | Login/logout redirect URLs |
| P1 | SSTI | If user input reaches template parsing |
| P2 | Clickjacking | Missing X-Frame-Options |
| P2 | Information Disclosure | Error pages, debug mode |

### Scope Definition

**Must audit:**
- Template files and rendering logic (html/template vs text/template)
- All uses of `template.HTML()`, `template.JS()`, `template.URL()` type casts
- Form handling and CSRF token validation
- Session creation, validation, and destruction
- Cookie attributes (Secure, HttpOnly, SameSite)
- Static file serving configuration
- Redirect logic after login/logout

**Key file patterns:**
```
**/templates/**/*.html, **/views/**/*.html
**/handler*.go, **/controller*.go
**/session*.go, **/auth*.go
**/middleware*.go
**/static*.go, **/assets*.go
```

---

## 4. CLI Tool

**Typical stack:** cobra / urfave/cli + os/exec + file I/O

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | Command Injection | CLI tools often shell out to other commands |
| P0 | Argument Injection | User arguments passed to subprocesses |
| P1 | Path Traversal | File operations with user-provided paths |
| P1 | Credential Exposure | Secrets in config files, environment, command history |
| P1 | Insecure Temp Files | Predictable temporary file names |
| P2 | Privilege Escalation | SUID/SGID behavior, sudo interactions |
| P2 | Symlink Attacks | Following symlinks to sensitive files |

### Scope Definition

**Must audit:**
- All `exec.Command` calls and how arguments are constructed
- File I/O operations with user-controlled paths
- Configuration file parsing (YAML, TOML, JSON) for injection points
- Secret/credential handling (reading, storing, passing to subprocesses)
- Temporary file creation patterns
- Signal handling and cleanup routines
- Plugin loading mechanisms (if any)

**Key file patterns:**
```
**/cmd/**/*.go (cobra command definitions)
**/main.go
**/config*.go
**/exec*.go, **/run*.go, **/shell*.go
```

---

## 5. Kubernetes Operator / Controller

**Typical stack:** controller-runtime / client-go / kubebuilder

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | RBAC Misconfiguration | Operator permissions too broad |
| P0 | Secret Exposure | Reading/creating secrets with sensitive data |
| P0 | Privilege Escalation | Creating pods with elevated privileges |
| P1 | Input Validation on CRDs | Malicious custom resource specs |
| P1 | SSRF via Controller Logic | Controller fetching external resources based on CR spec |
| P1 | Container Escape Vectors | SecurityContext not set or too permissive |
| P2 | Information Disclosure | Sensitive data in CRD status, events, or logs |
| P2 | DoS via Resource Creation | Creating unbounded resources from a single CR |

### Scope Definition

**Must audit:**
- RBAC manifests (ClusterRole, Role definitions)
- Reconcile loop logic (what does the operator create/modify/delete?)
- CRD validation (webhook validators, schema constraints)
- Secret reading and creation patterns
- Pod spec generation (SecurityContext, capabilities, volumes)
- External resource fetching in reconcile loops
- Finalizer logic (cleanup on deletion)

**Key file patterns:**
```
**/controllers/**/*.go, **/reconciler*.go
**/api/**/*.go (CRD type definitions)
**/webhook*.go
config/rbac/*.yaml
config/manager/*.yaml
**/main.go, **/suite_test.go
```

---

## 6. Blockchain / DeFi Application

**Typical stack:** cosmos-sdk / go-ethereum / tendermint

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | Integer Overflow/Underflow | Financial calculations with token amounts |
| P0 | Access Control on Transactions | Unauthorized transaction execution |
| P0 | Reentrancy-like Patterns | State modifications before external calls |
| P0 | Cryptographic Flaws | Key management, signature verification |
| P1 | Denial of Service | Transaction processing resource exhaustion |
| P1 | Front-Running Vectors | Transaction ordering dependency |
| P1 | Oracle Manipulation | External data feed trust assumptions |
| P2 | Information Disclosure | Private key leakage, transaction metadata |

### Scope Definition

**Must audit:**
- Transaction handlers / message handlers
- Token transfer and balance modification logic
- Signature verification and key management
- State machine transitions
- Mathematical operations on financial values (overflow checks)
- Consensus-related logic
- External data source (oracle) integration

---

## 7. Library / SDK

**Typical stack:** Pure Go library with public API

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | Input Validation on Public API | Library consumers pass untrusted data |
| P0 | Memory Safety | Unsafe pointer operations, buffer handling |
| P1 | Resource Exhaustion | Unbounded allocations from caller input |
| P1 | Cryptographic Misuse | If library provides crypto operations |
| P1 | Concurrency Safety | Race conditions in concurrent use |
| P2 | Error Handling | Panics that crash the caller's application |
| P2 | Dependency Chain | Transitive vulnerability exposure |

### Scope Definition

**Must audit:**
- All exported functions and methods (the public API surface)
- Input validation on every public function parameter
- Use of `unsafe` package
- Goroutine safety guarantees vs actual implementation
- Panic vs error return behavior
- Dependencies and their vulnerability status

---

## 8. File Processing Service

**Typical stack:** net/http + archive/zip / archive/tar + image processing

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | Path Traversal / Zip Slip | Archive extraction with crafted filenames |
| P0 | Command Injection | Shelling out to image/document processors |
| P1 | Decompression Bomb | Compressed files expanding to huge sizes |
| P1 | Symlink Attacks | Tar/zip entries that are symlinks |
| P1 | Resource Exhaustion | Processing large or malformed files |
| P2 | SSRF | If files contain URLs that are fetched |
| P2 | Content Type Confusion | File extension vs actual content mismatch |

### Scope Definition

**Must audit:**
- File upload handlers (size limits, type validation)
- Archive extraction logic (zip, tar, gzip)
- Filename sanitization
- External tool invocation for file processing
- Temporary file management
- Output file path construction

---

## 9. Gateway / Proxy Service

**Typical stack:** net/http / reverse proxy + middleware chain

### Priority Matrix

| Priority | Vulnerability Category | Reason |
|----------|----------------------|--------|
| P0 | SSRF | Core function involves making outbound requests |
| P0 | Authentication Bypass | Gateway auth checks must cover all routes |
| P0 | Header Injection | Forwarded headers manipulation |
| P1 | Request Smuggling | HTTP parsing inconsistencies between proxy and backend |
| P1 | Open Redirect | Routing based on user input |
| P1 | Information Disclosure | Leaking backend topology, internal headers |
| P2 | DoS | Slow-read attacks, connection exhaustion |
| P2 | TLS Configuration | Weak cipher suites, certificate validation |

### Scope Definition

**Must audit:**
- Routing logic and URL rewriting rules
- Header forwarding and sanitization (X-Forwarded-For, Host, etc.)
- Authentication and authorization at the gateway level
- Backend connection configuration (TLS, timeouts)
- Rate limiting and circuit breaker implementation
- WebSocket proxying (if applicable)
- Error handling and upstream timeout behavior
