---
title: "CLI Reference"
description: "Complete command reference for the Garmr CLI"
sidebar:
  order: 0
  label: "CLI Reference"
---

Complete command reference for the Garmr CLI.

## Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | | Config file path | `~/.garmr.yaml` |
| `--server` | | Garmr server URL | `http://localhost:8080` |
| `--output` | `-o` | Output format (table, json, yaml) | `table` |
| `--quiet` | `-q` | Suppress non-essential output | `false` |
| `--verbose` | `-v` | Verbose output | `false` |

---

## Commands

### garmr eval

Evaluate input against policies.

```bash
garmr eval --input <file> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input file (required, `-` for stdin) | |
| `--data` | `-d` | Inline JSON data | |
| `--policy` | `-p` | Specific policies to evaluate | |
| `--namespace` | `-n` | Policy namespace(s) to evaluate | |
| `--all-namespaces` | `-A` | Evaluate all namespaces | `false` |
| `--request-id` | | Request ID for audit correlation | |
| `--strict` | | Fail on warnings | `false` |
| `--trace` | | Enable evaluation trace | `false` |
| `--include-passed` | | Include passed rules in output | `false` |
| `--fail-on-warn` | | Exit code 2 on warnings | `false` |
| `--fail-fast` | | Stop on first failure | `false` |

**Examples:**

```bash
# Basic evaluation
garmr eval --input deployment.json

# Filter by namespace
garmr eval --input deployment.json -n security

# Multiple namespaces
garmr eval --input deployment.json -n security -n compliance

# JSON output for CI/CD
garmr eval --input deployment.json -o json

# With request ID for audit correlation
garmr eval --input deployment.json --request-id "gh-$GITHUB_RUN_ID"

# From stdin
cat deployment.json | garmr eval --input -

# Include all rules (passed and failed)
garmr eval --input deployment.json --include-passed

# Fail on warnings
garmr eval --input deployment.json --fail-on-warn
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | ALLOW - All policies passed |
| 1 | DENY - One or more policies failed |
| 2 | WARN - Warnings (with `--fail-on-warn`) |

---

### garmr validate

Validate policy syntax.

```bash
garmr validate <file-or-dir> [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--warn` | Show warnings | `false` |
| `--strict` | Treat warnings as errors | `false` |

**Examples:**

```bash
# Validate a policy file
garmr validate policies/security.cue

# Validate all policies in directory
garmr validate policies/

# Show warnings
garmr validate policies/ --warn

# Strict mode (warnings are errors)
garmr validate policies/ --strict
```

---

### garmr policy

Policy management commands.

#### garmr policy list

List loaded policies.

```bash
garmr policy list [flags]
```

**Flags:**

| Flag | Short | Description |
|------|-------|-------------|
| `--namespace` | `-n` | Filter by namespace |

**Examples:**

```bash
# List all policies
garmr policy list

# List as JSON
garmr policy list -o json

# Filter by namespace
garmr policy list -n security
```

#### garmr policy reload

Reload policies from disk.

```bash
garmr policy reload
```

**Examples:**

```bash
# Reload policies
garmr policy reload

# Check result
garmr policy reload -o json
```

#### garmr policy lock

Generate a lock file for a policy.

```bash
garmr policy lock <file> [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--version` | Version to record in lock file |

**Examples:**

```bash
# Generate lock file
garmr policy lock policies/release-gate.cue --version 1.0.0

# Creates: policies/release-gate.cue.lock
```

#### garmr policy validate-lock

Validate policy against its lock file.

```bash
garmr policy validate-lock <file> [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--recursive` | Check all policies in directory |

**Examples:**

```bash
# Validate single policy
garmr policy validate-lock policies/release-gate.cue

# Validate all policies recursively
garmr policy validate-lock --recursive policies/
```

#### garmr policy diff

Show differences between policy and lock file.

```bash
garmr policy diff <file>
```

**Examples:**

```bash
# Check if policy has changed
garmr policy diff policies/release-gate.cue
```

---

### garmr test

Run policy tests.

```bash
garmr test <policy-file> [test-file] [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--verbose` | `-v` | Show detailed output | `false` |
| `--recursive` | `-r` | Process directories recursively | `false` |
| `--filter` | | Filter tests by name | |
| `--output` | `-o` | Output format (text, json, tap) | `text` |
| `--fail-fast` | | Stop on first failure | `false` |

**Examples:**

```bash
# Run tests for a policy
garmr test policies/release-gate.cue

# Run all tests in directory
garmr test policies/ --recursive

# Filter by test name
garmr test policies/ --filter "valid release"

# TAP output for CI
garmr test policies/ -o tap

# JSON output
garmr test policies/ -o json

# Verbose output
garmr test policies/ -v
```

**Test File Format:**

```cue
// policies/release-gate_test.cue
{
    policy: "release-gate"

    tests: [{
        name: "valid release passes"
        input: {
            kind: "release"
            version: "1.0.0"
            tests: {passed: true}
        }
        expect: {
            decision: "allow"
            noViolations: true
        }
    }, {
        name: "missing tests fails"
        input: {
            kind: "release"
            version: "1.0.0"
        }
        expect: {
            decision: "deny"
            violations: [{id: "REL-001"}]
        }
    }]
}
```

---

### garmr docs

Documentation generation commands.

#### garmr docs generate

Generate markdown documentation from policies.

```bash
garmr docs generate <policy-dir> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--format` | `-f` | Output format | `generic-markdown` |
| `--output` | `-o` | Output directory | `./docs/policies` |
| `--recursive` | `-r` | Process recursively | `true` |
| `--author` | | Author for front matter | |

**Examples:**

```bash
# Generate docs from examples
garmr docs generate ./examples --output ./out/docs

# Specify format
garmr docs generate ./policies --format generic-markdown --output ./docs
```

---

### garmr health

Check server health.

```bash
garmr health [flags]
```

**Examples:**

```bash
# Check health
garmr health

# JSON output
garmr health -o json
```

---

### garmr version

Show version information.

```bash
garmr version
```

---

## Environment Variables

All flags can be set via environment variables with `GARMR_` prefix:

| Variable | Flag |
|----------|------|
| `GARMR_SERVER` | `--server` |
| `GARMR_OUTPUT` | `--output` |
| `GARMR_CONFIG` | `--config` |

**Example:**

```bash
export GARMR_SERVER=https://garmr.example.com:8080
export GARMR_OUTPUT=json

garmr eval --input deployment.json
```

---

## Configuration File

Create `~/.garmr.yaml` or `./garmr.yaml`:

```yaml
server: "localhost:8080"
output: "table"
insecure: false
```

---

## Output Formats

### Table (default)

Human-readable table format:

```
Decision: ✗ DENY

SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
----------------------------------------------------------------------------------------------------
HIGH         security/container-security    FAIL       SEC-001  Container is running as root
MEDIUM       security/container-security    FAIL       SEC-002  Root filesystem is not read-only

Evaluated 2 policies, 5 rules in 3.2ms
```

### JSON

Machine-readable JSON:

```json
{
  "decision": "deny",
  "request_id": "abc-123",
  "results": [
    {
      "policy_name": "container-security",
      "policy_namespace": "security",
      "rule_id": "SEC-001",
      "severity": "high",
      "passed": false,
      "message": "Container is running as root"
    }
  ],
  "metrics": {
    "evaluation_time_ns": 3200000,
    "policies_evaluated": 2,
    "rules_evaluated": 5
  }
}
```

### YAML

YAML output:

```yaml
decision: deny
request_id: abc-123
results:
  - policy_name: container-security
    policy_namespace: security
    rule_id: SEC-001
    severity: high
    passed: false
    message: Container is running as root
```

---

## Examples with Test Data

```bash
# Start server
make run

# Basic evaluation
garmr eval --input testdata/k8s-pod-secure.json

# Security policies only
garmr eval --input testdata/k8s-pod-secure.json -n security

# Advanced features (semver, datetime, forEach)
garmr eval --input testdata/semver-valid.json -n advanced

# Release pipeline gates
garmr eval --input testdata/release-input.json -n release

# Failing evaluations
garmr eval --input testdata/k8s-pod-insecure.json -n security
garmr eval --input testdata/autoscaler-invalid.json -n advanced

# JSON output
garmr eval --input testdata/k8s-pod-secure.json -o json | jq '.decision'

# List policies
garmr policy list
garmr policy list -n security

# Generate documentation
garmr docs generate ./examples --output ./out/docs
```
