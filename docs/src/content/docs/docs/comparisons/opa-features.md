---
title: "Garmr vs OPA: Features"
description: "Feature comparison between Garmr and Open Policy Agent"
sidebar:
  order: 0
  label: "vs OPA: Features"
---

> **Last updated:** 2026-02-14

## Overview

[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) is the industry-standard general-purpose policy engine, using the Rego language. Garmr is a purpose-built policy evaluation engine using [CUE](https://cuelang.org/), designed specifically for infrastructure policy enforcement in CI/CD pipelines and platform engineering workflows.

This document compares their feature sets side-by-side and highlights capabilities unique to each.

---

## Feature Matrix

### Policy Language & Evaluation

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Policy language | CUE | Rego | CUE provides type safety; Rego provides logic programming |
| Input formats | **JSON and YAML** (auto-detected from extension, content, or Content-Type) | JSON only | **Garmr advantage** — YAML is native in K8s/DevOps workflows |
| Schema validation | Built-in (CUE type system) | None (Rego is untyped) | **Garmr advantage** — policies are validated against a schema before loading |
| Policy compilation | Pre-compiled to CUE values | Compiled to IR / WASM | Both compile before eval |
| Built-in functions | 30+ | 150+ | OPA has far more built-ins |
| Custom functions | Registered via Go API | Registered via Go API | Equivalent |
| Expression operators | 25+ (match, compare, forEach, contains, all/any/not) | Rego operators + comprehensions | Different paradigms |
| Data references | `input.` path resolution, `func` calls | `input`, `data`, imports | OPA's `data` document is more flexible |
| Partial evaluation | Not implemented | Compile API | OPA advantage |
| WASM compilation | Not implemented | Supported | OPA advantage |

### Decision Model

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Decision outcomes | **allow / deny / warn** | allow / deny (boolean) | **Garmr advantage** — see [Three-Outcome Decisions](#1-three-outcome-decisions-allow--deny--warn) |
| Decision structure | Structured response with per-rule results | Arbitrary JSON document | **Garmr advantage** — consistent, machine-readable format |
| CI/CD exit codes | 0=allow, 1=deny, 2=warn | User must implement | **Garmr advantage** — native pipeline integration |
| Dry-run mode | Built-in (deny -> warn, `[DRY RUN]` prefix) | User must implement in Rego | **Garmr advantage** |
| Fail-fast evaluation | Built-in (stop on first critical failure) | User must implement in Rego | **Garmr advantage** |

### Rule Metadata & Organization

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Rule severity levels | critical / high / medium / low / info | Not built-in | **Garmr advantage** — see [Structured Rule Metadata](#2-structured-rule-metadata) |
| Rule priority | Numeric priority per rule | Not built-in | **Garmr advantage** |
| Evaluation ordering | 4 modes: priority, severity, definition, priority-then-severity | Definition order only | **Garmr advantage** |
| Rule categories | Built-in field per rule | Not built-in | **Garmr advantage** |
| Rule tags | Built-in tag arrays per rule | Not built-in | **Garmr advantage** |
| Remediation guidance | Built-in `remediation` field per rule | Not built-in | **Garmr advantage** |
| Category/tag filtering | Request-time and policy-level include/exclude | Not built-in | **Garmr advantage** |
| Policy namespaces | Built-in namespace hierarchy | Package system | Both provide organization |

### Target Matching & Exceptions

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Resource selectors | Built-in (kind, apiGroup, names, labels, namespaces, wildcards) | User must implement in Rego | **Garmr advantage** — see [Declarative Target Matching](#3-declarative-target-matching) |
| Exception handling | Built-in (named exceptions with match selectors, expiry dates, reason) | User must implement in Rego | **Garmr advantage** — see [Exception System](#4-exception-system-with-expiry) |
| Label-based matching | Built-in with wildcard patterns | User must implement | **Garmr advantage** |

### Server & API

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| HTTP API | REST (evaluate, validate, policies, reload) | REST (data, policies, query, compile) | Both provide REST APIs |
| gRPC API | Planned | Not built-in (Envoy plugin provides gRPC) | — |
| API authentication | API key (header + Bearer token) | Bearer token, mTLS | OPA has more auth options |
| CORS | Configurable allowed origins | Not built-in | Garmr advantage |
| Rate limiting | Built-in token bucket | Not built-in | Garmr advantage |
| Request body size limits | Configurable | Not built-in | Garmr advantage |
| TLS | Configurable cert/key | Configurable cert/key | Equivalent |
| Health checks | K8s probes (/healthz, /readyz, /livez) + legacy | /health with bundle awareness | Both provide health checks |
| OpenAPI / Swagger | Built-in spec + Swagger UI | Not built-in | Garmr advantage |
| Audit logging | Structured JSON with request ID correlation | Decision logs (remote push) | OPA's remote push is more mature |

### Policy Management

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Policy loading | Filesystem directory | Filesystem, REST API, bundles | OPA is more flexible |
| Hot reload | `/v1/policies/reload` endpoint | Bundle polling, REST API | Both support hot reload |
| Policy bundles | Not implemented | Full bundle system with signing | **OPA advantage** |
| Bundle discovery | Not implemented | Discovery service | **OPA advantage** |
| Lock files | Built-in (`garmr policy lock`) for GitOps | Not built-in | **Garmr advantage** — see [GitOps Lock Files](#5-gitops-lock-files) |
| Policy validation | `garmr validate` via API | `opa check` (local) | Both provide validation |
| Policy push | Not yet implemented | REST API `PUT /v1/policies` | OPA advantage |

### CLI & CI/CD Integration

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| CLI eval | `garmr eval --input file.json` | `opa eval -d policy.rego -i input.json` | Both provide CLI eval |
| Client-server model | CLI -> HTTP API -> Server | Embedded or REST API | **Garmr advantage** — see [CI/CD-Native CLI](#6-cicd-native-cli) |
| Exit codes | Semantic (0/1/2) | User-defined | **Garmr advantage** |
| Output formats | Table, JSON, YAML | JSON, pretty, raw | Both support multiple formats |
| Policy testing | `garmr test` with CUE test suites | `opa test` with Rego tests | Both provide testing frameworks |
| Test coverage | Not yet implemented | `opa test --coverage` | OPA advantage |
| Benchmarking | Load test suite included | `opa bench` | Both provide benchmarking |

### Observability & Operations

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Metrics | Prometheus-compatible (via plugin) | Built-in Prometheus endpoint | OPA is more mature |
| Tracing | OpenTelemetry (via plugin) | Not built-in | Garmr advantage (via plugin) |
| Decision logging | File-based structured JSON | Remote push to HTTP server | OPA's remote push is more production-ready |
| Status reporting | Health checks | Status API with bundle info | OPA provides more detail |

### Deployment & Integration

| Feature | Garmr | OPA | Notes |
|---|---|---|---|
| Deployment modes | CLI + HTTP server | Library, daemon, sidecar, WASM | OPA is more flexible |
| Kubernetes admission | Not implemented | Gatekeeper / OPA-Envoy | **OPA advantage** |
| Envoy integration | Not implemented | OPA-Envoy plugin | **OPA advantage** |
| Container image | Containerfile provided | Official Docker images | Both containerized |
| Plugin system | Go plugin architecture (10 plugins) | Go plugin + WASM | Both extensible |

---

## Features Unique to Garmr

### 1. Three-Outcome Decisions: Allow / Deny / Warn

**This is Garmr's most significant differentiator.**

OPA returns a boolean — `allow: true` or `allow: false`. If you want anything beyond binary yes/no, you must build it yourself in Rego. This leads to a common real-world problem: teams either block everything (too strict, slows velocity) or allow everything with advisory notes (too loose, no enforcement).

Garmr has three first-class decision outcomes:

| Decision | Meaning | CLI Exit Code | CI/CD Behavior |
|---|---|---|---|
| `allow` | All rules passed | `0` | Pipeline continues |
| `deny` | A deny-enforcement rule failed | `1` | Pipeline fails |
| `warn` | A warn-enforcement rule failed, no deny failures | `2` | Pipeline continues (unless `--fail-on-warn`) |

**Why this matters:**

- **Gradual rollout of new policies.** Deploy a new security policy with `enforcement: action: "warn"` first. Teams see violations in CI output but builds don't break. Once teams have addressed violations, flip to `enforcement: action: "deny"`.
- **Severity-appropriate responses.** A missing `description` label is a warning. A privileged container is a deny. Both are violations, but they should have different consequences.
- **CI/CD exit code semantics.** `garmr eval` returns exit code 0 (allow), 1 (deny), or 2 (warn). CI pipelines can use standard `$?` checking. The `--fail-on-warn` flag lets strict environments treat warnings as failures.
- **Dry-run mode.** Setting `enforcement: dryRun: true` or passing `--dry-run` automatically downgrades deny to warn and prefixes messages with `[DRY RUN]` — allowing policy authors to test deny policies in production without breaking anything.

```cue
// In OPA, you'd write custom Rego to handle this:
// allow { ... }
// warn[msg] { ... }
// deny[msg] { ... }
// ...then write more Rego to combine them into a single decision.

// In Garmr, it's a single field:
enforcement: action: "warn"   // or "deny" or "audit"
```

### 2. Structured Rule Metadata

Every rule in Garmr carries built-in metadata that OPA requires you to implement yourself:

```cue
rules: [{
    id:          "SEC-001"
    description: "Containers must not run as root"
    severity:    "critical"        // critical | high | medium | low | info
    priority:    100                // numeric — controls evaluation order
    category:    "security"         // for filtering and reporting
    tags:        ["cis-benchmark", "pod-security"]
    remediation: "Set securityContext.runAsNonRoot: true"
    expr: { ... }
    message:     "Container %{name} runs as root"
}]
```

**Why this matters:**

- **Severity-based decisions.** The engine aggregates severity across all failed rules. A `critical` failure is qualitatively different from a `low` finding.
- **Evaluation ordering.** Rules can be evaluated by priority, by severity (critical first), by definition order, or priority-then-severity. This controls which violations appear first and which trigger fail-fast.
- **Category/tag filtering.** At evaluation time, you can include or exclude rules by category or tag — at both the policy level and the request level. For example, run only `cis-benchmark` tagged rules, or exclude `experimental` rules.
- **Remediation guidance.** When a rule fails, the response includes actionable remediation text. Developers don't just see "FAIL" — they see what to fix.
- **Structured reporting.** The response summary breaks down pass/fail counts by severity, category, and namespace. Dashboards can aggregate this without custom parsing.

In OPA, none of this is built-in. You must design your own metadata schema, embed it in Rego rules, and write helper rules to aggregate it. Every OPA deployment reinvents this differently.

### 3. Declarative Target Matching

Garmr policies declare which resources they apply to using structured selectors:

```cue
target: resources: [{
    kind:       "Deployment"
    apiGroup:   "apps/v1"
    namespaces: ["production", "staging"]
    labels: {
        "team": "platform"
    }
}]
```

The engine automatically matches input resources against these selectors, supporting wildcards (`*`), glob patterns, and label matching. If the input doesn't match any target selector, the policy is skipped entirely.

**Why this matters:**

- **Separation of targeting from logic.** Policy authors declare *what* the policy applies to separately from *what* it checks. This is clearer than embedding target checks inside Rego rule bodies.
- **Automatic scope narrowing.** Only applicable policies are evaluated, reducing unnecessary computation.
- **Familiar Kubernetes-style selectors.** Teams already think in terms of kinds, namespaces, and labels.

In OPA, targeting is written as Rego conditions inside the rule body. There's no standard way to declare policy scope, so every policy reimplements target matching differently.

### 4. Exception System with Expiry

Garmr has a built-in exception mechanism that allows temporary or permanent exemptions:

```cue
enforcement: {
    action: "deny"
    exceptions: [{
        name:   "legacy-migration"
        reason: "Legacy app migrating to non-root by Q2"
        match: {
            kind:  "Deployment"
            names: ["legacy-api"]
            namespaces: ["production"]
        }
        expiry: "2026-06-30T00:00:00Z"
    }]
}
```

**Why this matters:**

- **Time-bounded exceptions.** Exceptions automatically expire. No more "temporary" exemptions that last forever.
- **Documented rationale.** Each exception requires a `name` and `reason`, creating an audit trail.
- **Selector-scoped.** Exceptions apply only to matching resources, not globally.
- **No policy modification needed.** Adding an exception doesn't require editing rule logic — it's a sibling of the enforcement block.

In OPA, exceptions must be coded as Rego rules or managed as data documents. There's no standard pattern for expiring exceptions, documenting reasons, or scoping them to specific resources.

### 5. GitOps Lock Files

Garmr provides a lock file system for policy integrity in GitOps workflows:

```bash
# Generate a lock file with SHA256 checksum
garmr policy lock policies/security/container-security.cue --version 2.5.1

# Validate lock files in CI (exits 1 if checksums don't match)
garmr policy lock validate-lock policies/

# Compare policy with its lock file
garmr policy diff policies/security/container-security.cue
```

Lock file format:
```json
{
    "schemaVersion": "1.0",
    "checksum": "sha256:e3b0c44...",
    "version": "2.5.1",
    "updatedAt": "2026-02-14T15:30:00Z",
    "updatedBy": "jane@example.com",
    "source": {
        "file": "container-security.cue",
        "size": 15234
    }
}
```

**Why this matters:**

- **Tamper detection.** Lock files let you verify that a policy hasn't been modified since it was reviewed and approved.
- **GitOps-native.** Commit both the policy and its `.lock` file. CI can validate that lock files are up to date before deployment.
- **Version tracking.** Lock files carry a version field, so you can track which version of a policy is deployed.
- **On-demand reload.** When Garmr detects a lock file checksum change, it knows a reload is needed — no polling required.

OPA uses bundle manifests with revision fields, which serve a similar purpose but require a bundle server infrastructure. Garmr's approach works with plain Git repositories.

### 6. CI/CD-Native CLI

Garmr's CLI is designed as a client to the Garmr server, making it a first-class CI/CD tool:

```bash
# CI pipeline step: evaluate a Kubernetes manifest
garmr eval --input deployment.yaml -n security --fail-on-warn -o json

# Exit code tells the pipeline what to do:
#   0 = allow  -> pipeline continues
#   1 = deny   -> pipeline fails
#   2 = warn   -> pipeline continues (or fails with --fail-on-warn)

# Validate policies before merging
garmr validate policies/*.cue

# Verify lock files are up to date
garmr policy validate-lock policies/

# Check server health (with wait for startup)
garmr health --wait --timeout 30s
```

**Why this matters:**

- **Client-server architecture.** The CLI calls the API. Policies live on the server. CI jobs don't need local policy files — they send input to a central policy server and get decisions back. This means one source of truth for policies across all pipelines.
- **Semantic exit codes.** Standard CI tools (GitHub Actions, GitLab CI, Jenkins) use exit codes to determine step success/failure. Garmr's 0/1/2 exit codes map directly to allow/deny/warn without wrapper scripts.
- **Multiple output formats.** `--output json` for machine parsing, `--output table` for human readability, `--output yaml` for compatibility.
- **Request ID correlation.** `--request-id $CI_JOB_ID` links policy decisions back to the CI job that triggered them, enabling end-to-end audit trails.

OPA's `opa eval` command evaluates locally — it doesn't call a server. For centralized policy evaluation, you must write your own HTTP client or use `curl`. There's no standard exit code convention.

### 7. CUE-Based Policy Schema Validation

Garmr validates policy files against a CUE schema before loading them. Invalid policies are rejected with specific error messages pointing to the exact field and constraint that failed.

**Why this matters:**

- **Catch errors early.** Typos, wrong types, missing required fields — all caught at policy load time, not at evaluation time.
- **Self-documenting.** The schema defines what a valid policy looks like. New policy authors can read the schema to understand available fields, types, and constraints.
- **IDE support.** CUE has LSP support, so editors can provide autocompletion and inline validation for policy files.

Rego is untyped. A typo in a variable name creates a new variable instead of an error. Missing fields silently evaluate to `undefined`. These are common sources of subtle policy bugs.

---

## Features Unique to OPA

| Feature | Description | Impact |
|---|---|---|
| **Rego language** | Purpose-built logic programming language with 10+ years of ecosystem | Massive community, tooling, and learning resources |
| **Policy bundles** | Atomic policy distribution with signing, versioning, and delta updates | Production-grade policy distribution at scale |
| **Bundle discovery** | Centralized configuration management for OPA instances | Fleet management of OPA deployments |
| **Partial evaluation** | Pre-compile policies for specific unknowns | Significant performance optimization for complex policies |
| **WASM compilation** | Compile Rego to WebAssembly for edge/browser execution | Run policies anywhere — browser, CDN, edge nodes |
| **Kubernetes Gatekeeper** | Admission controller with constraint templates | Native K8s policy enforcement at the API server |
| **Envoy integration** | gRPC-based external authorization | Service mesh policy enforcement |
| **Decision log push** | Asynchronous log shipping to remote servers | Centralized audit at scale |
| **150+ built-in functions** | Comprehensive standard library | Covers virtually any policy logic need |
| **Test coverage** | `opa test --coverage` reports policy coverage | Quantify test completeness |
| **Playground** | Web-based Rego playground | Learning and sharing policies |
| **Status API** | Reports bundle activation status and errors | Operational visibility |
| **Ecosystem maturity** | 10+ years, CNCF graduated, wide adoption | Battle-tested in production at scale |

---

## When to Choose Garmr Over OPA

Garmr is a better fit when:

1. **You need graduated enforcement** — warn first, deny later. OPA's binary model requires custom Rego scaffolding to achieve this.
2. **You want structured, consistent rule metadata** — severity, priority, categories, tags, remediation guidance — without reinventing it in every policy.
3. **Your workflow is CI/CD pipelines** — Garmr's CLI exit codes, client-server model, and output formats are designed for pipeline integration.
4. **Your team finds Rego difficult** — CUE's JSON-superset syntax is more approachable than Rego's Datalog-derived paradigm. [As noted by industry analysts](https://www.permit.io/blog/no-one-wants-to-write-rego): "Everyone loves policy as code, no one wants to write Rego."
5. **You want GitOps-native policy management** — lock files, checksum verification, and file-based policy loading work with plain Git repositories without bundle server infrastructure.
6. **You need declarative target matching and exceptions** — specifying what resources a policy applies to and which are exempt, with time-bounded exceptions.

## When to Choose OPA Over Garmr

OPA is a better fit when:

1. **You need Kubernetes admission control** — Gatekeeper is production-proven and widely adopted.
2. **You need policy distribution at scale** — OPA's bundle system with discovery, signing, and delta updates is mature.
3. **You need WASM or partial evaluation** — for edge deployment or complex policy optimization.
4. **You need a large built-in function library** — OPA has 150+ built-ins covering HTTP, JWT, graphs, and more.
5. **You need the ecosystem** — community policies, integrations, training materials, and commercial support.
6. **You need service mesh integration** — OPA-Envoy provides native Envoy external authorization.

---

## Sources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [OPA Policy Language](https://www.openpolicyagent.org/docs/policy-language)
- [OPA Integration Guide](https://www.openpolicyagent.org/docs/integration)
- [OPA Bundles](https://www.openpolicyagent.org/docs/management-bundles)
- [OPA Decision Logs](https://www.openpolicyagent.org/docs/management-decision-logs)
- [OPA FAQ](https://www.openpolicyagent.org/docs/faq)
- [OPA vs Cedar vs Zanzibar](https://www.osohq.com/learn/opa-vs-cedar-vs-zanzibar)
- ["Everyone Loves Policy as Code, No One Wants to Write Rego"](https://www.permit.io/blog/no-one-wants-to-write-rego)
- [OPA Alternatives — Cerbos](https://www.cerbos.dev/blog/opa-alternative)
