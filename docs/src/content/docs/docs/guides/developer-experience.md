---
title: "Developer Experience"
description: "Writing, testing, and debugging Garmr policies"
sidebar:
  order: 4
  label: "Developer Experience"
---

This guide covers how to develop, test, and validate policies for Garmr.

## Policy Development Workflow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Write Policy   │────▶│  Test Locally   │────▶│  Deploy to      │
│  (CUE)          │     │  (garmr eval)   │     │  Server         │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │                       │                       │
        ▼                       ▼                       ▼
   Validate with          Test with both          Generate lock
   garmr validate         pass & fail data        file for GitOps
```

---

## Writing Policies

### Policy Structure

```cue
package <namespace>

<policyName>: {
    apiVersion: "policy.garmr.io/v1"
    kind: "Policy"
    metadata: {
        name: "<policy-name>"
        namespace: "<namespace>"
        labels: {
            team: "<owning-team>"
            category: "<category>"
        }
    }
    spec: {
        description: "<what this policy enforces>"
        target: {
            resources: [<resource-kinds>]
        }
        rules: [<rules>]
        enforcement: {
            action: "deny" | "warn" | "audit"
        }
    }
}
```

### Rule Structure

```cue
{
    id: "RULE-001"                    // Unique within the policy
    description: "Rule description"   // Human-readable description
    severity: "critical" | "high" | "medium" | "low" | "info"
    expr: <expression>                // The check: exactly one operator
    // Optional:
    when: <expression>                // Rule applies only when this holds
    priority: 10                      // Lower is evaluated first
    message: "Failure message"        // Template, shown when the rule fails
    remediation: "How to fix it"
    url: "https://..."                // Documentation link
    category: "security"              // For evaluation filters and reports
    tags: ["pci-dss"]                 // For evaluation filters
}
```

See the [Policy Schema reference](/garmr/docs/reference/policy-schema/) for
the operators and every field.

### Example: Security Policy

```cue
package security

containerSecurity: {
    apiVersion: "policy.garmr.io/v1"
    kind: "Policy"
    metadata: {
        name: "container-security"
        namespace: "security"
        labels: {
            team: "security"
            category: "containers"
        }
    }
    spec: {
        description: "Enforce container security best practices"
        target: resources: ["pod", "deployment"]
        rules: [
            {
                id: "SEC-001"
                description: "Containers must not run as privileged"
                severity: "critical"
                expr: {
                    forEach: {
                        path: "spec.containers"
                        as: "container"
                        condition: {
                            any: [
                                {match: {path: "container.securityContext.privileged", exists: false}},
                                {match: {path: "container.securityContext.privileged", equals: false}}
                            ]
                        }
                    }
                }
                message: "Container is running in privileged mode"
            },
            {
                id: "SEC-002"
                description: "Containers must have resource limits"
                severity: "high"
                expr: {
                    forEach: {
                        path: "spec.containers"
                        as: "container"
                        condition: {
                            all: [
                                {match: {path: "container.resources.limits.memory", exists: true}},
                                {match: {path: "container.resources.limits.cpu", exists: true}}
                            ]
                        }
                    }
                }
                message: "Container is missing resource limits"
            }
        ]
        enforcement: action: "deny"
    }
}
```

---

## Testing Policies Locally

### Start a Local Server

```bash
# Start with your policies
./bin/garmr-server --dev --policy-dir ./my-policies --log-format console

# Or use examples
./bin/garmr-server --dev --policy-dir ./example-policies --log-format console
```

### Validate Policy Syntax

`garmr validate` runs locally, with the same loader the server runs at startup, so no server is needed. A green result means the server will load the set. Files and directories are accepted (directories are loaded recursively). Schema errors, such as an unknown operator or a typo like `mach:`, are reported here, not at evaluation time. Add `--remote` to validate against a running server's `/v1/validate` instead.

```bash
# Validate a policy file
garmr validate my-policy.cue

# Validate multiple files
garmr validate policies/*.cue

# Validate a whole policy tree
garmr validate policies/
```

### Test Against Sample Data

Against the example policies, with fixtures from the repository:

```bash
# Should ALLOW
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security

# Should DENY
garmr eval --input testdata/real-world/k8s-pod-security-context-fail.yml -n security

# Include passed rules in output
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security --verbose

# JSON output for detailed inspection
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security -o json | jq
```

To check one policy in isolation, name it with `-p` (with its namespace in
`-n`): `garmr eval --input pod.json -n security -p container-security`.

---

## Creating Test Data

### Manual Test Data Creation

Create JSON files that represent the resources your policy will evaluate:

**Passing test case:**
```json
{
  "kind": "Deployment",
  "metadata": {
    "name": "web-app",
    "namespace": "production"
  },
  "spec": {
    "containers": [
      {
        "name": "app",
        "image": "registry.example.com/app:v1.0.0",
        "securityContext": {
          "privileged": false,
          "runAsNonRoot": true,
          "readOnlyRootFilesystem": true
        },
        "resources": {
          "limits": {
            "memory": "256Mi",
            "cpu": "500m"
          },
          "requests": {
            "memory": "128Mi",
            "cpu": "250m"
          }
        }
      }
    ]
  }
}
```

**Failing test case:**
```json
{
  "kind": "Deployment",
  "metadata": {
    "name": "insecure-app",
    "namespace": "default"
  },
  "spec": {
    "containers": [
      {
        "name": "app",
        "image": "untrusted-registry.com/app:latest",
        "securityContext": {
          "privileged": true
        }
      }
    ]
  }
}
```

### Generating Test Data

You can create a script to generate test data variations:

```bash
#!/bin/bash
# generate-testdata.sh

# Base template
BASE_TEMPLATE='{
  "kind": "Deployment",
  "metadata": {"name": "test-app"},
  "spec": {"containers": [{"name": "app", "image": "IMAGE"}]}
}'

# Generate passing case - allowed registry
echo "$BASE_TEMPLATE" | jq '.spec.containers[0].image = "registry.example.com/app:v1.0"' \
  > testdata/registry-pass.json

# Generate failing case - disallowed registry
echo "$BASE_TEMPLATE" | jq '.spec.containers[0].image = "docker.io/app:latest"' \
  > testdata/registry-fail.json

# Generate edge cases
echo "$BASE_TEMPLATE" | jq '.spec.containers[0].image = ""' \
  > testdata/registry-empty.json

echo "Generated test data files"
```

### Test Data for All Operators

Create systematic test data for each operator type:

```bash
testdata/
└── operators/
    ├── equals-pass.json        # Field equals expected value
    ├── equals-fail.json        # Field doesn't equal expected value
    ├── exists-pass.json        # Required field exists
    ├── exists-fail.json        # Required field missing
    ├── comparison-pass.json    # Numeric comparison passes
    ├── comparison-fail.json    # Numeric comparison fails
    ├── string-pass.json        # String pattern matches
    ├── string-fail.json        # String pattern doesn't match
    ├── set-pass.json           # Value in allowed set
    ├── set-fail.json           # Value not in allowed set
    ├── logical-pass.json       # Logical conditions pass
    ├── logical-fail.json       # Logical conditions fail
    ├── foreach-pass.json       # All array items pass
    ├── foreach-fail.json       # Some array items fail
    ├── length-pass.json        # Length within bounds
    ├── length-fail.json        # Length out of bounds
    ├── semver-pass.json        # Version satisfies constraint
    ├── semver-fail.json        # Version doesn't satisfy
    ├── datetime-pass.json      # Date/time valid
    ├── datetime-fail.json      # Date/time expired
    ├── crossfield-pass.json    # Cross-field comparison passes
    └── crossfield-fail.json    # Cross-field comparison fails
```

---

## Test Data Examples by Operator

### Existence Operators

**exists-pass.json**
```json
{
  "kind": "test",
  "metadata": {
    "name": "test-resource",
    "labels": {
      "app": "myapp",
      "env": "prod"
    }
  }
}
```

**exists-fail.json**
```json
{
  "kind": "test",
  "metadata": {
    "name": "test-resource"
  }
}
```

### Comparison Operators

**comparison-pass.json**
```json
{
  "kind": "test",
  "spec": {
    "replicas": 3,
    "minReplicas": 2,
    "maxReplicas": 10
  }
}
```

**comparison-fail.json**
```json
{
  "kind": "test",
  "spec": {
    "replicas": 1,
    "minReplicas": 2,
    "maxReplicas": 10
  }
}
```

### String Operators

**string-pass.json**
```json
{
  "kind": "test",
  "spec": {
    "image": "registry.example.com/app:v1.0.0",
    "name": "my-application-service",
    "email": "user@example.com"
  }
}
```

**string-fail.json**
```json
{
  "kind": "test",
  "spec": {
    "image": "docker.io/untrusted:latest",
    "name": "x",
    "email": "invalid-email"
  }
}
```

### forEach Operator

**foreach-pass.json**
```json
{
  "kind": "Pod",
  "spec": {
    "containers": [
      {
        "name": "app",
        "resources": {"limits": {"memory": "256Mi"}}
      },
      {
        "name": "sidecar",
        "resources": {"limits": {"memory": "64Mi"}}
      }
    ]
  }
}
```

**foreach-fail.json**
```json
{
  "kind": "Pod",
  "spec": {
    "containers": [
      {
        "name": "app",
        "resources": {"limits": {"memory": "256Mi"}}
      },
      {
        "name": "sidecar"
      }
    ]
  }
}
```

### Semver Operator

**semver-pass.json**
```json
{
  "kind": "release",
  "version": "2.1.5",
  "apiVersion": "2.0.0"
}
```

**semver-fail.json**
```json
{
  "kind": "release",
  "version": "0.9.5-beta.1",
  "apiVersion": "1.0.0"
}
```

### Datetime Operator

**datetime-pass.json**
```json
{
  "kind": "certificate",
  "expiresAt": "2026-12-31T23:59:59Z",
  "createdAt": "2024-01-01T00:00:00Z"
}
```

**datetime-fail.json**
```json
{
  "kind": "certificate",
  "expiresAt": "2024-01-01T00:00:00Z",
  "createdAt": "2020-01-01T00:00:00Z"
}
```

### Cross-field Comparison

**crossfield-pass.json**
```json
{
  "kind": "autoscaler",
  "spec": {
    "minReplicas": 2,
    "maxReplicas": 10,
    "resources": {
      "requests": {"memory": 128},
      "limits": {"memory": 256}
    }
  }
}
```

**crossfield-fail.json**
```json
{
  "kind": "autoscaler",
  "spec": {
    "minReplicas": 10,
    "maxReplicas": 5,
    "resources": {
      "requests": {"memory": 512},
      "limits": {"memory": 256}
    }
  }
}
```

---

## Automated Testing

The built-in `garmr test` command runs policy test suites locally without a server, using the same evaluation engine the server uses — see the [CLI Reference](/garmr/docs/guides/cli/#garmr-test) for the test file format and `example-policies/real-world/release-gate_test.cue` for a worked example:

```bash
garmr test ./policies --recursive
```

For end-to-end pipeline checks you can also evaluate test inputs against a running server (the `testdata/operators/` paths and `test`/`advanced` namespaces below are placeholders for your own policies and data):

```bash
#!/bin/bash
# test-policies.sh

set -e

SERVER_URL="${GARMR_SERVER:-http://localhost:8080}"
PASS=0
FAIL=0

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

test_case() {
    local file=$1
    local expected_decision=$2
    local namespace=$3

    echo -n "Testing $file (expect: $expected_decision)... "

    ARGS="--input $file -o json"
    if [ -n "$namespace" ]; then
        ARGS="$ARGS -n $namespace"
    fi

    RESULT=$(./bin/garmr eval $ARGS 2>/dev/null || true)
    DECISION=$(echo "$RESULT" | jq -r '.decision')

    if [ "$DECISION" = "$expected_decision" ]; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC} (got: $DECISION)"
        FAIL=$((FAIL + 1))
    fi
}

echo "Running policy tests..."
echo ""

# Operator tests
echo "=== Existence Operators ==="
test_case "testdata/operators/exists-pass.json" "allow" "test"
test_case "testdata/operators/exists-fail.json" "deny" "test"

echo ""
echo "=== Comparison Operators ==="
test_case "testdata/operators/comparison-pass.json" "allow" "test"
test_case "testdata/operators/comparison-fail.json" "deny" "test"

echo ""
echo "=== String Operators ==="
test_case "testdata/operators/string-pass.json" "allow" "test"
test_case "testdata/operators/string-fail.json" "deny" "test"

echo ""
echo "=== Set Operators ==="
test_case "testdata/operators/set-pass.json" "allow" "test"
test_case "testdata/operators/set-fail.json" "deny" "test"

echo ""
echo "=== Logical Operators ==="
test_case "testdata/operators/logical-pass.json" "allow" "test"
test_case "testdata/operators/logical-fail.json" "deny" "test"

echo ""
echo "=== forEach Operator ==="
test_case "testdata/operators/foreach-pass.json" "allow" "advanced"
test_case "testdata/operators/foreach-fail.json" "deny" "advanced"

echo ""
echo "=== Length Operator ==="
test_case "testdata/operators/length-pass.json" "allow" "advanced"
test_case "testdata/operators/length-fail.json" "deny" "advanced"

echo ""
echo "=== Semver Operator ==="
test_case "testdata/operators/semver-pass.json" "allow" "advanced"
test_case "testdata/operators/semver-fail.json" "deny" "advanced"

echo ""
echo "=== Datetime Operator ==="
test_case "testdata/operators/datetime-pass.json" "allow" "advanced"
test_case "testdata/operators/datetime-fail.json" "deny" "advanced"

echo ""
echo "=== Cross-field Comparison ==="
test_case "testdata/operators/crossfield-pass.json" "allow" "advanced"
test_case "testdata/operators/crossfield-fail.json" "deny" "advanced"

echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
```

---

## Debugging Policies

### Inspect what actually ran

```bash
# Which rules ran, which were skipped, and whether fail-fast stopped early
garmr eval --input resource.json -o json | jq '.summary, .evaluation_mode'

# Include passing rules, not just violations
garmr eval --input resource.json --verbose
```

A per-rule execution trace is not available. `--trace` existed as a flag but
never emitted anything and has been removed; see `TODO.md` for what a real
implementation would need.

### Check Policy Loading

```bash
# List loaded policies
garmr policy list

# Check specific namespace
garmr policy list -n security

# Verify policy details
curl http://localhost:8080/v1/policies | jq '.policies[] | select(.name == "container-security")'
```

### Check Target Matching

If a policy isn't being evaluated, check target filtering:

```bash
# See which policies match a resource
garmr eval --input resource.json -o json | jq '.metrics.policies_evaluated'

# Evaluate without namespace filter to see all matching
garmr eval --input resource.json -o json | jq '[.results[].policy_name] | unique'
```

### Common Issues

**Policy not loading:**
```bash
# Check for CUE syntax errors
cue vet my-policy.cue

# Check Garmr validation (schema, operators, load-time checks)
garmr validate my-policy.cue
```

**Policy not matching:**
```bash
# Check resource kind matches target
cat resource.json | jq '.kind'

# Check policy target
grep -A5 "target:" my-policy.cue
```

**Unexpected failures:**
```bash
# Include passed rules to see full picture
garmr eval --input resource.json --verbose -o json | jq '.results'
```

---

## IDE Setup

### VS Code

Install the CUE extension for syntax highlighting:

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "CUE"
4. Install "CUE" by cue-lang

**settings.json:**
```json
{
  "[cue]": {
    "editor.formatOnSave": true,
    "editor.defaultFormatter": "cue-lang.cue"
  }
}
```

### JetBrains IDEs

1. Install the CUE plugin from the marketplace
2. Associate `.cue` files with CUE language

---

## Policy Development Best Practices

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Policy name | kebab-case | `container-security` |
| Rule ID | PREFIX-NNN | `SEC-001`, `REL-002` |
| Namespace | lowercase | `security`, `release` |

### Rule ID Prefixes

| Prefix | Domain |
|--------|--------|
| SEC | Security |
| REL | Release/Deployment |
| COM | Compliance |
| NET | Networking |
| RES | Resources |
| LAB | Labeling/Metadata |

### Severity Guidelines

| Severity | Use When |
|----------|----------|
| critical | Security vulnerabilities, data exposure risk |
| high | Important requirements, production blockers |
| medium | Best practices, recommended standards |
| low | Nice-to-have, optimization suggestions |
| info | Informational, documentation |

### Message Guidelines

Write clear, actionable messages:

```cue
// Bad
message: "Failed"

// Good
message: "Container must specify resource limits for memory and CPU"

// Better: a template names the offending element
message: "container {{c.name}} has no memory limit; set resources.limits.memory"
```

Messages are templates: `{{path}}` inserts an input field, `{{c.name}}` a
field of the element a `forEach` alias `c` points at (the message is then
rendered once per failing element), and `{{.length}}`, `{{.count}}`,
`{{.version}}`, `{{.datetime}}` or a `func` `bind` name insert the value the
check used. See [Messages](/garmr/docs/reference/policy-schema/#messages).
