# Garmr

A CUE-based policy evaluation engine for enforcing governance, security, and compliance policies across your infrastructure and CI/CD pipelines.

## Overview

Garmr provides a flexible, type-safe policy engine that uses [CUE](https://cuelang.org/) for policy definition. It supports:

- **20+ condition operators** for flexible rule construction
- **Target filtering** to apply policies to specific resource types
- **Namespace organization** for team-based policy management
- **Hot reload** for zero-downtime policy updates
- **Audit logging** with request correlation for compliance
- **CI/CD integration** via CLI and REST API

## Quick Start

### Installation

```bash
# Build from source
make build

# Binaries are in ./bin/
./bin/garmr-server --help
./bin/garmr --help
```

### Start the Server

```bash
# Start with example policies
./bin/garmr-server --policy-dir ./examples --audit-path /var/log/garmr/audit.log

# Development mode with console logging
./bin/garmr-server --dev --policy-dir ./examples --log-format console
```

### Evaluate a Resource

```bash
# Using the CLI
./bin/garmr eval --input testdata/k8s-pod-secure.json

# With namespace filter
./bin/garmr eval --input testdata/k8s-pod-secure.json -n security

# JSON output for CI/CD
./bin/garmr eval --input testdata/k8s-pod-secure.json -o json

# With request ID for audit correlation
./bin/garmr eval --input testdata/k8s-pod-secure.json --request-id "pipeline-12345"
```

### Using the REST API

```bash
# Evaluate a resource
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: pipeline-12345" \
  -d '{"input": {"kind": "Pod", "metadata": {"name": "web"}}}'

# List loaded policies
curl http://localhost:8080/v1/policies

# Reload policies (hot reload)
curl -X POST http://localhost:8080/v1/policies/reload
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/GETTING-STARTED.md) | First steps with Garmr |
| [Policy Schema](docs/POLICY-SCHEMA.md) | Complete reference for condition operators |
| [Target & Namespace Filtering](docs/FILTERING.md) | How to scope policies to resources |
| [CLI Reference](docs/CLI.md) | Complete CLI command reference |
| [REST API Reference](docs/REST-API.md) | HTTP API endpoints and examples |
| [CI/CD Integration](docs/CI-CD-PIPELINE-INTEGRATION.md) | Pipeline integration patterns |
| [Developer Experience](docs/DEVELOPER-EXPERIENCE.md) | Writing and testing policies |
| [Roadmap](docs/ROADMAP.md) | Future features and integrations |

## Example Policy

```cue
package security

containerSecurity: {
    apiVersion: "policy.garmr.io/v1"
    kind: "Policy"
    metadata: {
        name: "container-security"
        namespace: "security"
    }
    spec: {
        description: "Enforce container security best practices"
        target: resources: ["pod", "deployment"]
        rules: [
            {
                id: "SEC-001"
                description: "Containers must not run as root"
                severity: "high"
                expr: {
                    forEach: {
                        path: "spec.containers"
                        as: "container"
                        condition: {
                            match: {
                                path: "container.securityContext.runAsNonRoot"
                                equals: true
                            }
                        }
                    }
                }
                message: "Container is running as root"
            }
        ]
        enforcement: action: "deny"
    }
}
```

## Key Features

### Condition Operators

| Category | Operators |
|----------|-----------|
| Existence | `exists`, `absent` |
| Equality | `equals` |
| Comparison | `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual` |
| String | `contains`, `hasPrefix`, `hasSuffix`, `pattern` (regex) |
| Set | `in`, `notIn` |
| Logical | `all`, `any`, `not` |
| Advanced | `forEach`, `length`, `semver`, `datetime`, `compare` (cross-field) |

### Target Filtering

Apply policies only to specific resource types:

```cue
target: {
    resources: [
        "pod",
        "deployment",
        {
            kind: "configmap"
            namespaces: ["production"]
            labels: {env: "prod"}
        }
    ]
}
```

### Namespace Organization

Organize policies by team or function:

```
policies/
├── security/       # Security team policies
├── compliance/     # Compliance requirements
├── platform/       # Platform team standards
└── release/        # Release gate policies
```

### Audit Logging

Every evaluation is logged with:
- Request ID for correlation
- Decision (allow/deny/warn)
- Violations count
- Resource metadata
- Client information

## Project Structure

```
garmr/
├── cmd/
│   ├── garmr/             # CLI client
│   └── garmr-server/       # HTTP server
├── internal/
│   ├── engine/         # Policy evaluation engine
│   ├── server/         # HTTP handlers
│   └── client/         # Go client library
├── examples/           # Example policies
│   ├── advanced/       # Advanced feature examples
│   ├── release/        # Release gate policies
│   ├── security/       # Security policies
│   └── test/           # Test policies
├── testdata/           # Test input files
│   └── operators/      # Operator-specific tests
├── schemas/            # CUE schema definitions
└── docs/               # Documentation
```

## Configuration

### Server Configuration

```yaml
# config.yaml
http_addr: ":8080"
policy_dir: "/etc/garmr/policies"
audit:
  enabled: true
  path: "/var/log/garmr/audit.log"
log:
  level: "info"
  format: "json"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GARMR_HTTP_ADDR` | HTTP listen address | `:8080` |
| `GARMR_POLICY_DIR` | Policy directory | - |
| `GARMR_AUDIT_ENABLED` | Enable audit logging | `true` |
| `GARMR_AUDIT_PATH` | Audit log path | `/var/log/garmr/audit.log` |
| `GARMR_LOG_LEVEL` | Log level | `info` |

## License

Apache 2.0

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.