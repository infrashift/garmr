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

- CUE-based policy engine with 20+ condition operators and built-in functions
- Three-outcome decisions: pass, fail, warn
- Fail-fast evaluation, category/tag filtering, exception handling
- Timeout enforcement and dry-run mode
- CUE context pool for thread-safe concurrent evaluation
- Regex pattern caching

### Condition Operators

- **Existence:** `exists`, `absent`
- **Equality:** `equals`
- **Comparison:** `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`
- **String:** `contains`, `hasPrefix`, `hasSuffix`, `pattern`
- **Set:** `in`, `notIn`
- **Logical:** `all`, `any`, `not`
- **Advanced:** `forEach`, `length`, `semver`, `datetime`, `compare`

### Built-in Functions (30+)

- **Aggregates:** sum, min, max, avg
- **String:** len, lower, upper, contains, startsWith, endsWith, matches, trim, split, join, regex
- **Encoding:** base64Decode, base64Encode
- **Time:** now, duration, parseTime, format
- **Type:** typeOf, isType
- **Object:** hasKey, keys, values
- **Network:** cidr, cidrContains, cidrOverlap, ipVersion
- **Kubernetes:** unitsParse
- **Array:** flatten, unique, sort, filter, lookup
- **Versioning:** semver
- **Path:** jsonPath

### APIs

- HTTP REST API for policy evaluation, management, and health checks

### CLI

- Policy evaluation against a running server with `garmr eval`
- Policy testing framework with `garmr test` (CUE-based test files, TAP/JSON output; runs locally)
- Documentation generation with `garmr docs generate` (markdown output; runs locally)
- Policy reload, listing, and management commands

### Security & Networking

- TLS for HTTP (minimum TLS 1.2)
- API key authentication
- Service-mesh caller identity: SPIFFE URI parsed from `X-Forwarded-Client-Cert` (XFCC) and recorded as `principal` on every audit entry
- Configurable CORS
- Rate limiting (per-second + burst)
- Request body size limits
- Panic recovery middleware (returns 500 + structured log instead of dropping the connection)

### Policy Management

- Target-based policy filtering (kind, apiGroup, names, labels, annotations, namespaces)
- Namespace-based policy organization
- Hot reload via API and CLI
- Lock file support for GitOps workflows

### Storage Backends

- **Filesystem** (built-in) -- local file watching with inotify
- **S3 / MinIO** (built-in) -- AWS S3 and MinIO support, polling-based change detection

### Observability

- JSON audit logging with request correlation, file rotation, and SPIFFE
  `principal` + W3C `trace_id` on every entry
- Prometheus metrics endpoint (evaluations, latency histograms, violations,
  cache, rate limits, recovered panics, Go runtime) served from `/metrics`
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
- Concurrent rule evaluation within a policy
- Worker pool management
- Context cancellation support

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
