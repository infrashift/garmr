# Q Policy Agent

A CUE-based policy-as-code agent that provides a modern alternative to Open Policy Agent (OPA) and HashiCorp Sentinel.

## Overview

Q leverages CUE's powerful type system and constraint solving to define and evaluate policies. Unlike Rego or Sentinel, policies in Q benefit from:

- **Schema-first validation**: Policies are validated at write time, not runtime
- **Type safety**: CUE's type lattice catches errors before deployment
- **Composability**: Policies unify cleanly without conflicts
- **Determinism**: Hermetic evaluation with no hidden state

## Quick Start

### Installation

```bash
# Build from source
make build
make install

# Or use Docker
docker pull ghcr.io/yourorg/q-policy-agent:latest
```

### Start the Server

```bash
# Development mode
q-server --dev --policy-dir ./examples

# Production
q-server --config /etc/q/config.yaml
```

### Evaluate Policies

```bash
# Evaluate a resource
q eval --input deployment.json

# Evaluate with specific policy
q eval --input pod.json --policy security/no-privileged

# JSON output for CI/CD
q eval --input resource.json -o json
```

## CLI Reference

### q eval

Evaluate input against policies.

```bash
q eval [flags]

Flags:
  -i, --input string      Input file (- for stdin)
  -d, --data string       Inline JSON data
  -p, --policy strings    Specific policies to evaluate
  -n, --namespace string  Policy namespace
      --strict            Fail on warnings
      --trace             Enable evaluation trace
      --dry-run           Evaluate without enforcement
  -o, --output string     Output format (table, json, yaml)
```

### q validate

Validate policy files.

```bash
q validate [files...] [flags]

Flags:
      --warn    Show warnings
      --strict  Fail on warnings
```

### q policy

Manage policies.

```bash
q policy list                    # List all policies
q policy get <name>              # Get policy details
q policy push <file>             # Push policy to server
q policy delete <name>           # Delete policy
q policy reload                  # Reload from disk
```

### q health

Check server health.

```bash
q health [flags]

Flags:
      --wait            Wait for server to be ready
      --timeout duration Timeout when waiting (default 30s)
```

## Policy Schema

Policies are defined in CUE using the Q schema:

```cue
package mypolicies

import "github.com/yourorg/q-policy-agent/schemas:policy"

noPrivileged: policy.#Policy & {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "no-privileged-containers"
        namespace: "security"
        labels: {
            "category": "container-security"
            "compliance": "cis-benchmark"
        }
    }
    spec: {
        description: "Containers must not run in privileged mode"
        
        target: {
            resources: [{
                apiGroup: "apps"
                kind: "Deployment" | "StatefulSet"
            }]
        }
        
        rules: [{
            id: "SEC-001"
            description: "Privileged mode must be disabled"
            severity: "critical"
            expr: {
                forEach: {
                    collection: "spec.containers"
                    as: "container"
                    expr: {
                        compare: {
                            left: path: "item.securityContext.privileged"
                            op: "!="
                            right: literal: true
                        }
                    }
                }
            }
            message: "Container '{{.container.name}}' cannot run privileged"
        }]
        
        enforcement: {
            action: "deny"
            exceptions: [{
                name: "kube-system"
                reason: "System components"
                match: {
                    namespaces: ["kube-system"]
                }
            }]
        }
    }
}
```

## Expression Language

Q supports these expression types:

| Expression | Description |
|------------|-------------|
| `all` | All sub-expressions must pass (AND) |
| `any` | At least one must pass (OR) |
| `not` | Negation |
| `exists` | Field must exist |
| `absent` | Field must not exist |
| `match` | Regex pattern matching |
| `compare` | Value comparison (==, !=, <, >, in, etc.) |
| `contains` | Collection contains value |
| `forEach` | Iterate over collection |
| `ref` | Reference external data |
| `cue` | Raw CUE expression |

## API Reference

### gRPC API

The server exposes gRPC services on port 9090:

- `PolicyService` - Evaluate, Validate, Compile
- `PolicyManagementService` - CRUD operations
- `DataService` - External data management
- `HealthService` - Health checks

### REST API

HTTP gateway on port 8080:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/evaluate` | Evaluate input |
| POST | `/v1/validate` | Validate policy |
| GET | `/v1/policies` | List policies |
| PUT | `/v1/policies/{ns}/{name}` | Create/update policy |
| DELETE | `/v1/policies/{ns}/{name}` | Delete policy |
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Evaluate Policies
  run: |
    q eval --input ${{ github.workspace }}/manifests/*.yaml \
           --server ${{ secrets.Q_SERVER }} \
           -o json > results.json
    
    if jq -e '.decision == "deny"' results.json; then
      echo "Policy violations found"
      exit 1
    fi
```

### GitLab CI

```yaml
policy-check:
  image: ghcr.io/yourorg/q-policy-agent:latest
  script:
    - q eval --input manifests/ --strict
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## Configuration

See `config.example.yaml` for all options.

Key settings:

```yaml
grpc_addr: ":9090"
http_addr: ":8080"
policy_dir: "/etc/q/policies"

tls:
  enabled: true
  cert: "/etc/q/tls/cert.pem"
  key: "/etc/q/tls/key.pem"

log:
  level: "info"
  format: "json"
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   q CLI     │────▶│  Q Server   │────▶│ CUE Engine  │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │             │
              ┌─────▼─────┐ ┌─────▼─────┐
              │  Policies │ │   Data    │
              │   (CUE)   │ │  Sources  │
              └───────────┘ └───────────┘
```

## Comparison with OPA/Sentinel

| Feature | Q | OPA | Sentinel |
|---------|---|-----|----------|
| Language | CUE | Rego | Sentinel |
| Type System | Strong | Weak | Weak |
| Schema Validation | Built-in | External | None |
| Composition | Unification | Override | Import |
| Learning Curve | Moderate | Steep | Moderate |

## License

Apache 2.0
