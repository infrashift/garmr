# Garmr Roadmap

This document outlines the planned features and integrations for Garmr.

## Current Version (v1)

### Core Features ✅
- CUE-based policy engine with 20+ condition operators
- HTTP REST API for policy evaluation
- CLI for local evaluation and CI/CD integration
- Target-based policy filtering (kind, apiGroup, labels, namespaces)
- Namespace-based policy organization
- Hot reload via API and CLI
- JSON audit logging with request correlation
- Lock file support for GitOps workflows
- Documentation generation (`q docs generate --format generic-markdown`)

### Condition Operators ✅
- Existence: `exists`, `absent`
- Equality: `equals`
- Comparison: `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`
- String: `contains`, `hasPrefix`, `hasSuffix`, `pattern`
- Set: `in`, `notIn`
- Logical: `all`, `any`, `not`
- Advanced: `forEach`, `length`, `semver`, `datetime`, `compare`

---

## Planned Features

### gRPC API

Native gRPC support for high-performance integrations.

**Features**
- Protocol Buffers service definitions
- Streaming evaluation for batch processing
- Bidirectional streaming for real-time policy updates
- gRPC-Gateway for REST compatibility
- mTLS authentication
- gRPC health checking protocol

**Service Definitions**
```protobuf
service PolicyService {
  rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);
  rpc EvaluateBatch(stream EvaluateRequest) returns (stream EvaluateResponse);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
  rpc ReloadPolicies(ReloadRequest) returns (ReloadResponse);
  rpc WatchPolicies(WatchRequest) returns (stream PolicyEvent);
}
```

---

### Documentation Generation Formats

Extended markdown format support for static site generators.

**Planned Formats**
- `hugo-markdown` - Hugo static site generator with YAML front matter
- `astro-markdown` - Astro framework with MDX support
- `github-markdown` - GitHub-flavored markdown with badges
- `gitlab-markdown` - GitLab-flavored markdown with CI integration
- `docusaurus-markdown` - Docusaurus with admonitions and tabs

**Features**
- Custom template support
- Mermaid diagram generation for rule flow
- Auto-generated examples from test data
- Cross-reference linking between policies
- Version diff documentation

---

### Plugin System

A pluggable architecture for extending Garmr functionality.

**Signed Plugins**
- Ed25519 signature verification for plugin integrity
- Plugin manifest with capabilities declaration
- Sandbox execution environment

**Plugin Types**
- Storage backends
- Audit destinations
- Custom condition operators
- Authentication providers
- Notification handlers

---

### Storage Backends

Support for loading policies from various storage systems.

**S3 / Object Storage**
- AWS S3, Google Cloud Storage, Azure Blob Storage
- MinIO for on-premises deployments
- Automatic sync with configurable polling interval
- Support for versioned buckets

**Consul KV**
- HashiCorp Consul key-value store integration
- Watch-based automatic reload
- ACL token authentication

**Git Repository**
- Direct Git repository integration
- Branch/tag selection
- SSH and HTTPS authentication
- Webhook-triggered reload

**Database Backends**
- PostgreSQL with JSONB storage
- DuckDB for embedded analytics
- Policy versioning and history

---

### Infrastructure Integrations

**HashiCorp Ecosystem**

*Terraform Integration*
- Pre-plan policy evaluation
- Post-plan validation before apply
- Sentinel policy migration tools
- terraform-provider-q for native integration

*Vault Integration*
- Policy-based secret access control
- Dynamic policy based on Vault identity
- Audit log correlation with Vault audit

*Consul Integration*
- Service mesh authorization policies
- Intention validation
- Service catalog governance

**Configuration Management**

*Ansible Integration*
- Pre-playbook policy gates
- Role and task validation
- Inventory compliance checks
- ansible-lint integration

*Puppet/Chef Integration*
- Catalog validation
- Resource compliance checking

---

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

### Audit & Observability

**Kafka Audit Sink**
- Stream decision audit logs to Kafka topics
- Configurable partitioning (by namespace, resource type)
- Schema registry integration (Avro/Protobuf)
- At-least-once delivery guarantees

**Elasticsearch/OpenSearch**
- Direct audit log shipping
- Index lifecycle management
- Kibana dashboard templates

**Splunk Integration**
- HTTP Event Collector (HEC) support
- Structured event format
- Pre-built dashboards

**OpenTelemetry**
- Distributed tracing integration
- Metrics export (Prometheus format)
- Baggage propagation for context

**Prometheus Metrics**
- Evaluation latency histograms
- Policy pass/fail counters
- Cache hit rates
- Active policy counts

---

### Policy Development

**Policy Testing Framework**
- `q test` command for policy unit tests
- Table-driven test definitions
- Coverage reporting
- Snapshot testing

**Policy Linting**
- Best practice enforcement
- Complexity analysis
- Dead rule detection
- Performance suggestions

**Policy Simulation**
- Dry-run mode with detailed traces
- What-if analysis
- Impact assessment for policy changes

**IDE Integration**
- VS Code extension
- Language server protocol (LSP)
- Inline validation and completion
- Policy documentation hover

---

### Enterprise Features

**Multi-Tenancy**
- Tenant isolation
- Per-tenant policy namespaces
- Resource quotas

**High Availability**
- Clustered deployment
- Leader election for background tasks
- Shared policy cache

**Authentication & Authorization**
- OIDC/OAuth2 authentication
- RBAC for policy management
- API key management

**Policy Governance**
- Approval workflows
- Change audit trail
- Policy lifecycle management
- Compliance reporting

---

### Performance Optimizations

**Rate Limiting**
- Global request rate limiting
- Per-client rate limiting (by IP, header, or certificate)
- Configurable burst limits
- Exempt client list
- HTTP middleware integration

**Parallel Evaluation**
- Concurrent policy evaluation
- Worker pool management
- Context cancellation support

**Caching**
- LRU result cache with TTL
- Input normalization for cache hits
- Distributed cache (Redis)

**Compilation Optimizations**
- Pre-compiled policy bundles
- Incremental compilation
- Hot path optimization

---

## Integration Priority

### Phase 1: Foundation
1. gRPC API
2. Plugin system architecture
3. S3 storage backend
4. Additional markdown formats

### Phase 2: Observability
1. Kafka audit sink
2. Prometheus metrics
3. OpenTelemetry integration

### Phase 3: HashiCorp
1. Terraform integration
2. Vault integration
3. Consul integration

### Phase 4: Kubernetes
1. Admission controller
2. CRD support
3. Operator

### Phase 5: Enterprise
1. Multi-tenancy
2. High availability
3. Advanced authentication

---

## Contributing

We welcome contributions! If you're interested in working on any of these features:

1. Check existing issues for the feature
2. Open a discussion to coordinate approach
3. Submit a proposal for larger features
4. Follow contribution guidelines

## Feedback

Have suggestions for the roadmap? Open an issue with the `roadmap` label or start a discussion.