---
title: "Getting Started"
description: "Build, run, and evaluate your first policies with Garmr"
sidebar:
  order: 1
  label: "Getting Started"
---

## Build

```bash
# Build both binaries
make build

# This creates:
# - bin/garmr-server  (the HTTP/REST server)
# - bin/garmr     (the CLI client)
```

## Running the Server

### Option 1: Development Mode (easiest)

```bash
# Start server with example policies
./bin/garmr-server --dev --policy-dir ./example-policies --log-format console

# Server listens on:
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
export GARMR_POLICY_DIR=./example-policies
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

### Using the CLI

The `garmr` CLI talks to the server over the REST API. By default it targets `http://localhost:8080`; override with `--server` or the `GARMR_SERVER` environment variable.

## Example Test Data

The `release-gate` policy (`example-policies/real-world/release-gate.cue`) targets
`kind: "Release"` and reads nested fields like `quality.tests.*.passed`,
`quality.coverage.percentage`, `security.vulnerabilities.*`, `provenance.*`,
`targetEnvironment`, and `approvals.count`/`approvals.leadApproved`. A passing
input looks like this — save as `testdata/release-input.json`:

```json
{
  "kind": "Release",
  "apiVersion": "release.garmr.io/v1",
  "metadata": {
    "name": "my-service",
    "namespace": "production"
  },
  "version": "v1.2.3",
  "targetEnvironment": "production",
  "quality": {
    "tests": {
      "unit": {"passed": true},
      "integration": {"passed": true},
      "e2e": {"passed": true}
    },
    "coverage": {"percentage": 85}
  },
  "security": {
    "vulnerabilities": {"critical": 0, "high": 0}
  },
  "provenance": {
    "signed": true,
    "buildPlatform": "github-actions"
  },
  "approvals": {
    "count": 2,
    "leadApproved": true
  }
}
```

### Gates versus advisory

The `release` namespace ships two policies that share the same rule set but
enforce different severities:

| Policy             | Rules evaluated           | Action | On failure      |
|--------------------|---------------------------|--------|------------------|
| `release-gate`     | critical-severity rules   | deny   | Blocks promotion |
| `release-advisory` | non-critical rules (high) | warn   | Flags for review |

Both run by default when you evaluate against the `release` namespace. Every
violation is reported (no short-circuit), and decisions aggregate:

- All rules pass → **ALLOW**
- Only advisory rules fail → **WARN**
- Any gate (critical) rule fails → **DENY**

### Example: Passing Input

Use `--verbose` (or `-v`) to see every rule result, not just failures.
Rules within each policy evaluate in priority order:

```bash
./bin/garmr eval --verbose \
  --input testdata/release-input.json \
  --namespace release

# Expected output:
# Decision: ✓ ALLOW
#
# SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
# ----------------------------------------------------------------------------------------------------
# CRITICAL     release/release-gate           PASS       REL-001
# CRITICAL     release/release-gate           PASS       REL-002
# CRITICAL     release/release-gate           PASS       REL-004
# CRITICAL     release/release-gate           PASS       REL-007
# HIGH         release/release-advisory       PASS       REL-006
# HIGH         release/release-advisory       PASS       REL-003
# HIGH         release/release-advisory       PASS       REL-005
```

### Example: Advisory-only failure → WARN

Coverage below 80% is a quality signal, not a blocker. The input at
`testdata/release-input-fail-1.yml` only trips `REL-003`:

```bash
./bin/garmr eval --input testdata/release-input-fail-1.yml --namespace release

# Decision: ⚠ WARN
#
# HIGH         release/release-advisory       FAIL       REL-003  code coverage must be >= 80%
```

### Example: Critical failure → DENY (all violations reported)

```bash
./bin/garmr eval --input testdata/release-input-fail-3.json --namespace release

# Decision: ✗ DENY
#
# CRITICAL     release/release-gate           FAIL       REL-004  release must have zero critical a...
# HIGH         release/release-advisory       FAIL       REL-003  code coverage must be >= 80%
# HIGH         release/release-advisory       FAIL       REL-005  release must have signed provenan...
```

## HTTP API

The server also exposes a REST API. See the [REST API Reference](/garmr/docs/guides/rest-api/) for full details.

### Evaluate via HTTP

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "kind": "Release",
      "version": "v1.2.3",
      "targetEnvironment": "production",
      "quality": {
        "tests": {
          "unit": {"passed": true},
          "integration": {"passed": true},
          "e2e": {"passed": true}
        },
        "coverage": {"percentage": 85}
      },
      "security": {"vulnerabilities": {"critical": 0, "high": 0}},
      "provenance": {"signed": true, "buildPlatform": "github-actions"},
      "approvals": {"count": 2, "leadApproved": true}
    },
    "namespace": "release",
    "include_passed": true
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

For more details, see the [CI/CD Integration guide](/garmr/docs/guides/ci-cd-pipeline-integration/).

### GitHub Actions

```yaml
- name: Policy Check
  run: |
    ./bin/garmr eval --input deployment.json -o json > result.json
    if [ "$(jq -r '.decision' result.json)" = "deny" ]; then
      echo "Policy violations found:"
      jq -r '.results[] | select(.passed == false) | "  - [\(.severity)] \(.ruleId): \(.message)"' result.json
      exit 1
    fi
    echo "All policies passed"
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
./bin/garmr test --policy-dir ./example-policies

# Test specific policy
./bin/garmr test --policy ./example-policies/real-world/release-gate.cue
```

## Generate Documentation

Generate markdown documentation from policies:

```bash
# Generate docs for all policies
./bin/garmr docs --policy-dir ./example-policies --output-dir ./docs/policies

# Generate for specific format
./bin/garmr docs --policy-dir ./example-policies --format docusaurus --output-dir ./docs
```

## Configuration File Reference

`config.yaml`:

```yaml
# Server settings
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
  type: "filesystem"  # filesystem, s3
```

## Troubleshooting

### Server won't start

```bash
# Check if port is in use
lsof -i :8080

# Use a different port
./bin/garmr-server --http-addr :8081
```

### Policies not loading

```bash
# Check policy syntax
./bin/garmr validate --policy-dir ./example-policies

# Enable debug logging
./bin/garmr-server --log-level debug --log-format console
```

### Connection refused

```bash
# Check server is running
curl http://localhost:8080/health

# CLI with custom server URL
./bin/garmr eval --server http://localhost:8080 --input data.json
```
