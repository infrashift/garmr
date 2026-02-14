# Garmr - Quick Start Guide

## Build

```bash
# Build both binaries
make build

# This creates:
# - bin/garmr-server  (the gRPC/HTTP server)
# - bin/garmr     (the CLI client)
```

## Running the Server

### Option 1: Development Mode (easiest)

```bash
# Start server with example policies
./bin/garmr-server --dev --policy-dir ./examples --log-format console

# Server listens on:
# - gRPC: localhost:9090
# - HTTP: localhost:8080
```

### Option 2: With Config File

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit as needed, then:
./bin/garmr-server --config config.yaml
```

### Option 3: Environment Variables

```bash
export GARMR_POLICY_DIR=./examples
export GARMR_GRPC_ADDR=:9090
export GARMR_HTTP_ADDR=:8080
export GARMR_LOG_LEVEL=debug

./bin/garmr-server
```

## Evaluating Policies

### Using HTTP API (recommended for now)

The HTTP API is the simplest way to evaluate policies:

```bash
# Health check
curl http://localhost:8080/health

# Evaluate a file
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": '"$(cat testdata/release-input.json)"'}'

# Evaluate with namespace filter
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": '"$(cat testdata/release-input.json)"', "namespace": "release"}'

# Pretty print with jq
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": '"$(cat testdata/release-input.json)"'}' | jq .
```

### Using the garmr-eval Script

A convenience script is provided:

```bash
# Make executable
chmod +x scripts/garmr-eval

# Evaluate
./scripts/garmr-eval testdata/release-input.json

# With namespace
./scripts/garmr-eval testdata/release-input.json release

# Custom server
GARMR_SERVER=http://localhost:8080 ./scripts/garmr-eval testdata/release-input.json
```

### Using the CLI (requires protobuf setup)

The full CLI uses gRPC which requires protobuf code generation.
For now, use the HTTP API or the garmr-eval script above.

## Example Test Data

Create a file `testdata/release-input.json`:

```json
{
  "deployment": {
    "name": "my-service",
    "namespace": "production",
    "version": "1.2.3",
    "environment": "production"
  },
  "tests": {
    "passed": true,
    "count": 150,
    "failures": 0
  },
  "coverage": 85,
  "security": {
    "criticalFindings": 0,
    "highFindings": 2,
    "scanCompleted": true
  },
  "approvals": [
    {
      "approver": "alice@example.com",
      "role": "release-manager",
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "artifact": {
    "image": "registry.example.com/my-service:1.2.3",
    "digest": "sha256:abc123...",
    "signed": true
  }
}
```

### Example: Passing Input

```bash
./bin/garmr eval --input testdata/release-input.json

# Expected output:
# Decision: ✓ ALLOW
#
# SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
# ----------------------------------------------------------------------------------------------------
# CRITICAL     release/release-gate           PASS       REL-001  
# HIGH         release/release-gate           PASS       REL-002  
# CRITICAL     release/release-gate           PASS       REL-003  
# MEDIUM       release/release-gate           PASS       REL-004  
```

### Example: Failing Input

Create `testdata/release-input-fail.json`:

```json
{
  "deployment": {
    "name": "my-service",
    "namespace": "production",
    "version": "1.2.3",
    "environment": "production"
  },
  "tests": {
    "passed": false,
    "count": 150,
    "failures": 5
  },
  "coverage": 65,
  "security": {
    "criticalFindings": 2,
    "highFindings": 10,
    "scanCompleted": true
  },
  "approvals": []
}
```

```bash
./bin/garmr eval --input testdata/release-input-fail.json

# Expected output:
# Decision: ✗ DENY
#
# SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
# ----------------------------------------------------------------------------------------------------
# CRITICAL     release/release-gate           FAIL       REL-001  Test suite did not pass
# HIGH         release/release-gate           FAIL       REL-002  Code coverage below 80%
# CRITICAL     release/release-gate           FAIL       REL-003  Critical security vulnerabilities found
# MEDIUM       release/release-gate           FAIL       REL-004  Missing required approval
```

## HTTP API

The server also exposes a REST API:

### Evaluate via HTTP

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "tests": {"passed": true},
      "coverage": 85,
      "security": {"criticalFindings": 0},
      "approvals": [{"approver": "alice@example.com"}]
    },
    "namespace": "release"
  }'
```

### List Policies

```bash
curl http://localhost:8080/v1/policies
```

### Health Check

```bash
curl http://localhost:8080/health
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Policy Check
  run: |
    ./bin/garmr eval --input deployment.json -o json > result.json
    if [ "$(jq -r '.decision' result.json)" = "deny" ]; then
      echo "❌ Policy violations found:"
      jq -r '.results[] | select(.passed == false) | "  - [\(.severity)] \(.ruleId): \(.message)"' result.json
      exit 1
    fi
    echo "✅ All policies passed"
```

### GitLab CI

```yaml
policy-check:
  script:
    - ./bin/garmr eval --input deployment.json || exit 1
  allow_failure: false
```

## Policy Testing

Run policy tests with the `test` command:

```bash
# Test all policies
./bin/garmr test --policy-dir ./examples

# Test specific policy
./bin/garmr test --policy ./examples/release-pipeline.cue
```

## Generate Documentation

Generate markdown documentation from policies:

```bash
# Generate docs for all policies
./bin/garmr docs --policy-dir ./examples --output-dir ./docs/policies

# Generate for specific format
./bin/garmr docs --policy-dir ./examples --format docusaurus --output-dir ./docs
```

## Configuration File Reference

`config.yaml`:

```yaml
# Server settings
grpc_addr: ":9090"
http_addr: ":8080"

# Policy loading
policy_dir: "/policies"
data_dir: "/data"

# TLS (optional)
tls:
  enabled: false
  cert: "/path/to/cert.pem"
  key: "/path/to/key.pem"

# Logging
log:
  level: "info"    # debug, info, warn, error
  format: "json"   # json, console

# Storage backend (optional)
storage:
  type: "filesystem"  # filesystem, s3, consul
  
# Plugins (optional)
plugins:
  dir: "/plugins"
  enabled:
    - prometheus
    - otel
```

## Troubleshooting

### Server won't start

```bash
# Check if ports are in use
lsof -i :9090
lsof -i :8080

# Use different ports
./bin/garmr-server --grpc-addr :9091 --http-addr :8081
```

### Policies not loading

```bash
# Check policy syntax
./bin/garmr validate --policy-dir ./examples

# Enable debug logging
./bin/garmr-server --log-level debug --log-format console
```

### Connection refused

```bash
# Check server is running
curl http://localhost:8080/health

# CLI with custom server address
./bin/garmr eval --server localhost:9090 --input data.json
```