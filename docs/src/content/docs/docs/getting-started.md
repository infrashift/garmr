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

Audit logging is on by default and writes to `/var/log/garmr/audit.log`.
The server creates that directory at startup and **refuses to start** if it
can't, which is the normal case for a non-root user. Every local example
below therefore sets `--audit-path` (to `stdout`, or a writable file).

### Option 1: Development Mode (easiest)

```bash
# Build and start the server with the example policies
make dev

# ...which runs:
./bin/garmr-server --dev --policy-dir ./example-policies \
  --audit-path /tmp/garmr-audit/audit.log --log-format console

# Server listens on:
# - HTTP: localhost:8080
```

To watch decisions as they happen, use `--audit-path stdout` instead: audit
records go to stdout and application logs to stderr.

### Option 2: With Config File

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit as needed, then:
./bin/garmr-server --config config.yaml
```

`config.example.yaml` is written for a deployed server: it points
`policy_dir` at `/etc/garmr/policies` and the audit log at
`/var/log/garmr/audit.log`. For a local run, change `policy_dir` to
`./example-policies` and `audit.path` to `stdout` (or a writable path).
`make run-server` does this without editing anything: it starts the server
with `config.example.yaml` and overrides those two settings on the command
line (`--policy-dir ./example-policies --audit-path stdout`), since flags
take precedence over the config file.

### Option 3: Environment Variables

```bash
export GARMR_POLICY_DIR=./example-policies
export GARMR_HTTP_ADDR=:8080
export GARMR_LOG_LEVEL=debug
export GARMR_AUDIT_PATH=stdout

./bin/garmr-server
```

## Evaluating Policies

### Using HTTP API (recommended for now)

The HTTP API is the simplest way to evaluate policies:

```bash
# Health check
curl http://localhost:8080/health

# Evaluate a file against every loaded policy that targets it. With the
# example policies this is a DENY: many example policies target every kind
# ("*") and check fields a release doesn't have.
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": '"$(cat testdata/real-world/release-pass.json)"'}'

# Evaluate with namespace filter: only the release policies run (ALLOW)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": '"$(cat testdata/real-world/release-pass.json)"', "namespace": "release"}'

# Pretty print with jq
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": '"$(cat testdata/real-world/release-pass.json)"', "namespace": "release"}' | jq .
```

### Using the CLI

The `garmr` CLI is a thin client over the same REST API. `garmr eval` and the `garmr policy list`/`get`/`delete`/`reload` subcommands require a running server. By default the CLI targets `http://localhost:8080`; override with `--server` or the `GARMR_SERVER` environment variable.

These commands run entirely locally, with no server needed: `garmr validate` (add `--remote` to validate against a server instead), `garmr policy digest`, `garmr test`, `garmr docs generate`, and `garmr policy lock`/`validate-lock`/`diff`. That is what lets a CI job validate a checkout and compute its policy-set digest before anything is deployed.

## Example Test Data

The `release-gate` policy (`example-policies/real-world/release-gate.cue`) targets
`kind: "Release"` and reads nested fields like `quality.tests.*.passed`,
`quality.coverage.percentage`, `security.vulnerabilities.*`, `provenance.*`,
`targetEnvironment`, and `approvals.count`/`approvals.leadApproved`. A passing
input is provided at `testdata/real-world/release-pass.json`:

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
Policies are reported in name order, and rules within each policy in
priority order:

```bash
./bin/garmr eval --verbose \
  --input testdata/real-world/release-pass.json \
  --namespace release

# Expected output:
# Decision: ✓ ALLOW
#
# SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
# ----------------------------------------------------------------------------------------------------
# HIGH         release/release-advisory       PASS       REL-006
# HIGH         release/release-advisory       PASS       REL-003
# HIGH         release/release-advisory       PASS       REL-005
# CRITICAL     release/release-gate           PASS       REL-001
# CRITICAL     release/release-gate           PASS       REL-002
# CRITICAL     release/release-gate           PASS       REL-004
# CRITICAL     release/release-gate           PASS       REL-007
#
# Evaluated 2 policies, 7 rules in 44.293µs
```

### Example: Advisory-only failure → WARN

Coverage below 80% is a quality signal, not a blocker. The input at
`testdata/real-world/release-fail-1.yml` only trips `REL-003`:

```bash
./bin/garmr eval --input testdata/real-world/release-fail-1.yml --namespace release

# Decision: ⚠ WARN
#
# HIGH         release/release-advisory       FAIL       REL-003  code coverage must be >= 80%
#                                                                  ↳ Add tests to increase coverage above the 80% threshold
```

WARN exits `0`; only DENY (or an error) exits `1`.

### Example: Critical failure → DENY (all violations reported)

```bash
./bin/garmr eval --input testdata/real-world/release-fail-3.json --namespace release

# Decision: ✗ DENY
#
# HIGH         release/release-advisory       FAIL       REL-003  code coverage must be >= 80%
#                                                                  ↳ Add tests to increase coverage above the 80% threshold
# HIGH         release/release-advisory       FAIL       REL-005  release must have signed provenance w...
# CRITICAL     release/release-gate           FAIL       REL-004  release must have zero critical and h...
#                                                                  ↳ Remediate all critical and high vulnerabilities before release
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

For more details, see the [CI/CD Integration guide](/garmr/docs/guides/cicd/).

### GitHub Actions

```yaml
- name: Policy Check
  run: |
    # Exit codes: 0 allow/warn, 1 deny, 2 the evaluation did not run
    rc=0
    ./bin/garmr eval --input deployment.json -o json > result.json || rc=$?
    case $rc in
      0) echo "All policies passed" ;;
      1)
        echo "Policy violations found:"
        jq -r '.results[] | select(.passed == false) | "  - [\(.severity)] \(.rule_id): \(.message)"' result.json
        exit 1 ;;
      *) echo "Policy evaluation failed (exit $rc)"; exit 2 ;;
    esac
```

### GitLab CI

```yaml
policy-check:
  script:
    # Exits 1 on DENY and 2 when the evaluation did not run (e.g. server
    # unreachable); either fails the job
    - ./bin/garmr eval --input deployment.json
  allow_failure: false
```

## Policy Testing

The `garmr test` command (local, no server needed) runs CUE test suites in
`*_test.cue` files using the same evaluation engine as the server. A suite
names the policy under test and asserts decisions and violations per input:

```cue
// my-policy_test.cue (no package clause — the server's policy loader
// ignores test files)
policy: "release/release-gate"

tests: [{
	name: "unapproved production release is denied"
	input: {
		kind:              "Release"
		version:           "v1.2.3"
		targetEnvironment: "production"
		// ...
		approvals: count: 1
	}
	expect: {
		decision: "deny"
		violations: [{id: "REL-007"}]
	}
}]
```

```bash
# Run the repo's example suite
./bin/garmr test example-policies/real-world/release-gate.cue

# Discover and run every *_test.cue under a directory
./bin/garmr test ./example-policies --recursive
```

See `example-policies/real-world/release-gate_test.cue` for a complete
suite, including template inputs and target-mismatch assertions.

## Generate Documentation

Generate markdown documentation from policies (runs locally, no server needed):

```bash
# Generate docs for all policies (recursive by default)
./bin/garmr docs generate ./example-policies --out-dir ./docs/policies

# Explicit format (only generic-markdown is currently supported)
./bin/garmr docs generate ./example-policies --format generic-markdown --out-dir ./docs/policies
```

## Configuration File Reference

`config.yaml`:

```yaml
# Server settings
http_addr: ":8080"

# Policy loading (selects the filesystem backend rooted here)
policy_dir: "/policies"

# Transport security: Garmr serves plain HTTP only. TLS/mTLS is the
# service mesh's (or a fronting proxy's) job.

# Logging
log:
  level: "info"    # debug, info, warn, error
  format: "json"   # json, console

# Audit trail: "stdout"/"stderr" stream it, anything else is a file path
audit:
  path: "stdout"

# Storage backend (optional). When storage.type is set, policy_dir is
# ignored and the root comes from storage.root (default "/policies"):
# storage:
#   type: "filesystem"   # the only implemented backend
#   root: "/policies"
```

See [Server Configuration](/garmr/docs/reference/configuration/) for every setting.

## Troubleshooting

### Server won't start

```bash
# Check if port is in use
lsof -i :8080

# Use a different port
./bin/garmr-server --http-addr :8081 --policy-dir ./example-policies --audit-path stdout

# "creating audit log directory: mkdir /var/log/garmr: permission denied"
# means the default audit path isn't writable: pass --audit-path stdout
# (or a writable file), or --audit=false
```

### Policies not loading

```bash
# Check policy syntax (runs locally; accepts files or directories)
./bin/garmr validate ./example-policies

# Enable debug logging
./bin/garmr-server --policy-dir ./example-policies --audit-path stdout \
  --log-level debug --log-format console
```

A policy set that fails to load is fatal at startup: the error names the
file and the failing check. A server started with no `policy_dir` (and no
`storage.type`) starts with zero policies and denies every evaluation.

### Connection refused

```bash
# Check server is running
curl http://localhost:8080/health

# CLI with custom server URL
./bin/garmr eval --server http://localhost:8080 --input data.json
```
