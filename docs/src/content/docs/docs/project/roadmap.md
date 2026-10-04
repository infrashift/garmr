---
title: "Roadmap"
description: "Current capabilities and planned features for Garmr"
sidebar:
  order: 0
  label: "Roadmap"
---

This document describes what Garmr can do today and where it's headed.

## Current Version (v1)

### Core Engine

- Policies written in CUE, with 20+ condition operators and 30+ built-in functions
- Three decisions: `allow`, `deny`, `warn`; each rule passes, fails, or fails with an evaluation error (an error never turns into a pass under `not` or `any`)
- Fail-fast evaluation, per-policy category/tag filtering and `maxRules`, policy-level exceptions with expiry
- Evaluation deadline (checked on every `forEach` element) and dry-run mode
- Load-time rejection of anything that would otherwise fail silently: unknown or multiple operators per expression, uncompilable regexes/semvers/datetimes, duplicate rule ids, duplicate `namespace/name`, exceptions that match everything
- Policies compiled once at load (CUE is used only at load) into Go evaluation trees; evaluation is lock-free and fully parallel against an immutable policy snapshot
- Regexes, semver/datetime literals, and literal sets precompiled at load; bounded LRU cache for runtime regex patterns

### Condition Operators

- **Expressions:** `all`, `any`, `not`, `match`, `compare`, `forEach`, `func` (exactly one per expression, schema-checked at load)
- **Existence:** `exists: true`, `exists: false`
- **Equality:** `equals`
- **Comparison:** `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`
- **String:** `contains`, `hasPrefix`, `hasSuffix`, `pattern`
- **Set:** `in`, `notIn`
- **Lists:** `containsAll`, `containsAny`, `subsetOf`, `unique`, `uniqueBy`, `sorted`
- **Advanced:** `length`, `semver`, `datetime`
- **Rule applicability:** rule `when`; `forEach` `where` filters and `count` ("at most one container may…")
- **Paths:** `[N]` indexes, `[*]` projections (`spec.containers[*].cpu`), quoted keys
- **Cross-field:** `compare` with equality, ordering, membership, string, `subsetOf`, semver and datetime operators; joins via nested `forEach`
- **Messages:** templates naming the failing element (`container {{c.name}} …`) and the value checked (`{{.count}}`, `{{.length}}`)

### Built-in Functions (30+)

- **Core:** len
- **Aggregates:** sum, min, max, avg
- **String:** lower, upper, trim, trimPrefix, trimSuffix, split, join, matches, format
- **Encoding:** base64Decode, base64Encode
- **Time:** now, duration, parseTime
- **Type:** typeOf, isType
- **Object:** hasKey, keys, values, lookup
- **Network:** cidrContains, cidrOverlap, ipVersion
- **Kubernetes:** unitsParse
- **Array:** flatten, unique, sort, filter

### APIs

- HTTP REST API for policy evaluation, management, and health checks

### CLI

- Policy evaluation against a running server with `garmr eval`
- Policy testing framework with `garmr test` (CUE-based test files, TAP/JSON output; runs locally)
- Documentation generation with `garmr docs generate` (markdown output; runs locally)
- Policy reload, listing, and management commands

### Security & Networking

- Plain HTTP only; TLS/mTLS is the service mesh's (or a fronting proxy's) job
- API key authentication
- Service-mesh caller identity: SPIFFE URI parsed from `X-Forwarded-Client-Cert` (XFCC) and recorded as `principal` on every audit entry
- Configurable CORS
- Rate limiting: global and per-client buckets (per-second + burst), keyed on the mesh identity, client IP, or a header; probes and `/metrics` exempt
- Request body size limits
- Panic recovery middleware (returns 500 + structured log instead of dropping the connection)

### Policy Management

- Target-based policy filtering (kind, apiGroup, names, labels, annotations, namespaces)
- Namespace-based policy organization
- Explicit, atomic, fail-closed policy reload via `POST /v1/policies/reload`
- Fleet reload with `garmr policy reload --servers … --expect-digest …`, which fails unless every instance converges on the expected policy-set digest
- Lock file support for GitOps workflows

### Storage Backends

- **Filesystem** (built-in) -- the policy directory, from a ConfigMap, PVC,
  CSI mount, or an init container that syncs from object storage

### Observability

- JSON audit logging to a rotated file or to stdout/stderr (for the
  platform's log pipeline), with request correlation and SPIFFE `principal`
  + W3C `trace_id` on every entry
- Prometheus metrics endpoint (evaluations, latency histograms, violations,
  policies loaded, reloads, rate limits, recovered panics, Go runtime) served from `/metrics`
- OpenTelemetry tracing via `otelhttp`:
  - Incoming `traceparent` is always extracted for log correlation
  - OTLP exporter is opt-in via `OTEL_EXPORTER_OTLP_ENDPOINT`
- Structured logging with slog / zap
- Health check endpoints (`/healthz`, `/readyz`, `/livez`)

---

## Planned Features

### Kubernetes Native

**Admission Controller**
- ValidatingWebhookConfiguration
- MutatingWebhookConfiguration (policy-based mutations)
- High-availability deployment

**Custom Resource Definitions**
- `Policy` CRD for GitOps workflows
- `PolicyBinding` for namespace-scoped policies
- `PolicyException` for approved violations

**Operator**
- Automatic policy sync from Git
- Status reporting on policy health
- Metrics and alerting integration

---

### Infrastructure Integrations

**Terraform Integration**
- Pre-plan policy evaluation
- Post-plan validation before apply
- Sentinel policy migration tools
- terraform-provider-garmr for native integration

---

### Policy Language (deferred OPA parity)

Reviewed 2026-10-03 and recorded in `TODO.md`; deliberately not done yet:

- **Per-rule exceptions and actions** -- exempt specific rules from an
  exception, and override `enforcement.action` per rule (one policy cannot
  mix deny and warn today)
- **`spec.inputSchema`** -- a CUE definition the input must satisfy,
  reported as a distinct invalid-input verdict
- **More builtins** -- x509 parsing, `jwt.decode`, `sha256`, `glob.match`,
  `replace`, JSON/YAML parse
- **Tooling** -- rule coverage in `garmr test`, a `garmr bench` wrapper
- **Embedding** -- a small public `pkg/garmr` (`Compile`, `Evaluate`)

Not pursued: runtime external data (`http.send`), bundle signing, partial
evaluation, WASM, Envoy ext_authz.

---

### Policy Development

**Policy Linting**
- Best practice enforcement
- Complexity analysis
- Dead rule detection
- Performance suggestions

**IDE Integration**
- VS Code extension
- Language server protocol (LSP)
- Inline validation and completion

---

### Performance Optimizations

**Parallel Rule Evaluation**
- Concurrent rule evaluation within a policy (requests already evaluate fully
  in parallel against a lock-free snapshot, and evaluation is cancelled at
  its deadline)

**Result Caching**
- LRU result cache with TTL
- Input normalization for cache hits

---

### Enterprise Features

**Multi-Tenancy**
- Tenant isolation
- Per-tenant policy namespaces
- Resource quotas

**High Availability (beyond today's stateless-replica model)**

The current model — N stateless pods fronted by a Service or mesh, each
loading policies from a shared backend — works for most deployments. The
planned items below address scenarios today's model does not cover:

- Leader election for scheduled background tasks (bulk re-evaluation,
  remote bundle pulls)
- Shared result cache across replicas for hot inputs
- Clustered deployment primitives for single-writer ops

**Authentication & Authorization**
- OIDC/OAuth2 authentication
- RBAC for policy management

**Policy Governance**
- Approval workflows
- Change audit trail
- Policy lifecycle management
- Compliance reporting

---

## Contributing

We welcome contributions! If you're interested in working on any of these features:

1. Check existing issues for the feature
2. Open a discussion to coordinate approach
3. Submit a proposal for larger features
4. Follow contribution guidelines

## Feedback

Have suggestions for the roadmap? Open an issue with the `roadmap` label or start a discussion.
