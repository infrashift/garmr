---
title: "Policy Schema Reference"
description: "Complete reference for Garmr condition operators"
sidebar:
  order: 0
  label: "Policy Schema"
---

Complete reference for Garmr condition operators with CLI and API examples.

## Overview

Garmr supports 20+ condition operators organized into:

- **Condition Operators**: Basic operations (exists, equals, comparison, string, set, logical)
- **Advanced Operators**: Complex operations (forEach, length, semver, datetime, compare)

## Input Formats

Garmr accepts input in both JSON and YAML formats.

### Supported Formats

| Format | Extensions | Content-Type |
|--------|------------|--------------|
| JSON | `.json` | `application/json` |
| YAML | `.yaml`, `.yml` | `application/x-yaml`, `application/yaml`, `text/yaml` |

### CLI Usage

```bash
# Auto-detect from file extension
garmr eval --input deployment.yaml -n security
garmr eval --input deployment.json -n security

# Explicit format flag
garmr eval --input deployment.txt --format yaml -n security

# Stdin with format hint
cat deployment.yaml | garmr eval --input - --format yaml -n security
```

### API Usage

```bash
# JSON input (default)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {...}, "namespace": "security"}'

# YAML input
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/x-yaml" \
  -d '
input:
  kind: pod
  metadata:
    name: my-pod
namespace: security
'
```

## Enforcement Actions

Policies specify an `enforcement.action` that determines behavior:

| Action | Description | CLI Exit Code |
|--------|-------------|---------------|
| `deny` | Block on any rule failure | 1 |
| `warn` | Log warning but allow | 0 |
| `audit` | Log only, always allow | 0 |

### Severity Levels

Rules specify severity to prioritize violations:

| Severity | Use Case |
|----------|----------|
| `critical` | Security vulnerabilities, compliance violations |
| `high` | Production stability risks |
| `medium` | Best practice violations |
| `low` | Minor issues |
| `info` | Recommendations |

---

## Condition Operators

Note: several example policies in the `condition-operators` namespace target all kinds (`*`), so an evaluation against that namespace can run multiple policies at once. The expected decisions below describe the rules of the operator being illustrated.

### exists / absent

Validates field presence or absence.

**Policy:** `example-policies/condition-operators/exists.cue`

```cue
expr: match: {
    path:   "requiredField"
    exists: true
}

expr: match: {
    path:   "deprecatedField"
    absent: true
}
```

**CLI:**
```bash
# Should ALLOW (required field present)
garmr eval -d '{"kind": "test-exists", "requiredField": "present", "metadata": {"name": "test"}}' -n condition-operators

# Should DENY (missing requiredField)
garmr eval -d '{"kind": "test-exists", "metadata": {"name": "test"}}' -n condition-operators
```

**curl (JSON):**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-exists", "requiredField": "present", "metadata": {"name": "test"}}, "namespace": "condition-operators"}'
```

**curl (YAML):**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/x-yaml" \
  -d '
input:
  kind: test-exists
  requiredField: present
  metadata:
    name: test
namespace: condition-operators
'
```

---

### equals

Validates exact field value (string, number, or boolean).

**Policy:** `example-policies/condition-operators/equals.cue`

```cue
expr: match: {
    path:   "status"
    equals: "active"
}

expr: match: {
    path:   "count"
    equals: 10
}

expr: match: {
    path:   "enabled"
    equals: true
}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "test-equals", "status": "active", "count": 10, "enabled": true}' -n condition-operators

# Should DENY (wrong status)
garmr eval -d '{"kind": "test-equals", "status": "inactive", "count": 10, "enabled": true}' -n condition-operators
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-equals", "status": "active", "count": 10, "enabled": true}, "namespace": "condition-operators"}'
```

---

### Comparison Operators

Numeric comparisons: `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`.

**Policy:** `example-policies/condition-operators/comparison.cue`

```cue
expr: match: {
    path:        "replicas"
    greaterThan: 0
}

expr: match: {
    path:               "replicas"
    greaterThanOrEqual: 2
}

expr: match: {
    path:            "memoryMB"
    lessThanOrEqual: 4096
}

expr: match: {
    path:     "cpuCores"
    lessThan: 8
}
```

**CLI:**
```bash
# Should ALLOW (replicas=3, memory=2048, cpu=4)
garmr eval -d '{"kind": "test-comparison", "replicas": 3, "memoryMB": 2048, "cpuCores": 4}' -n condition-operators

# Should DENY (replicas=1, memory=8192, cpu=16)
garmr eval -d '{"kind": "test-comparison", "replicas": 1, "memoryMB": 8192, "cpuCores": 16}' -n condition-operators
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-comparison", "replicas": 3, "memoryMB": 2048, "cpuCores": 4}, "namespace": "condition-operators"}'
```

---

### String Operators

String matching: `contains`, `hasPrefix`, `hasSuffix`, `pattern`.

**Policy:** `example-policies/condition-operators/string.cue`

```cue
expr: match: {
    path:      "image"
    hasPrefix: "gcr.io/"
}

expr: {
    not: match: {
        path:      "image"
        hasSuffix: ":latest"
    }
}

expr: match: {
    path:     "environment"
    contains: "prod"
}

expr: match: {
    path:    "metadata.name"
    pattern: "^[a-z][a-z0-9-]*[a-z0-9]$"
}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "test-string", "metadata": {"name": "web-api"}, "image": "gcr.io/project/app:v1.0.0", "environment": "production"}' -n condition-operators

# Should DENY (wrong registry, :latest tag)
garmr eval -d '{"kind": "test-string", "metadata": {"name": "web-api"}, "image": "docker.io/app:latest", "environment": "production"}' -n condition-operators
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-string", "metadata": {"name": "web-api"}, "image": "gcr.io/project/app:v1.0.0", "environment": "production"}, "namespace": "condition-operators"}'
```

---

### Set Operators

Set membership and array validation: `in`, `notIn`, `unique`, `uniqueBy`, `sorted`, `containsAll`, `subsetOf`.

**Policy:** `example-policies/condition-operators/set.cue`

```cue
expr: match: {
    path: "environment"
    in: ["development", "staging", "production"]
}

expr: match: {
    path: "region"
    notIn: ["cn-north-1", "cn-northwest-1", "ru-west-1"]
}
```

**CLI:**
```bash
# Should ALLOW (production, us-east-1)
garmr eval -d '{"kind": "test-set", "environment": "production", "region": "us-east-1", "tier": "premium"}' -n condition-operators

# Should DENY (unknown environment)
garmr eval -d '{"kind": "test-set", "environment": "test", "region": "us-east-1", "tier": "premium"}' -n condition-operators
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-set", "environment": "production", "region": "us-east-1", "tier": "premium"}, "namespace": "condition-operators"}'
```

#### Advanced Set Operators

Array validation operators. Element equality is numeric-aware (`1` and
`1.0` are the same value), and a non-array value at the path fails the
rule with a diagnostic.

**Policy:** `example-policies/condition-operators/set.cue` (the
`set-advanced` policy, targeting `kind: "test-set-advanced"`)

##### unique / uniqueBy

Validates no duplicate values in arrays.

```cue
// Simple array - no duplicate values
expr: match: {
    path:   "spec.ports"
    unique: true
}

// Array of objects - no duplicates by field (dot-notation paths supported)
expr: match: {
    path:     "spec.containers"
    uniqueBy: "name"
}
```

An element missing the `uniqueBy` field fails the rule. `unique: false`
places no constraint.

**Use Cases:**
- No duplicate port numbers in a service
- No duplicate container names in a pod
- No duplicate environment variable names

##### sorted

Validates array is in sorted order (`"asc"` or `"desc"`). Equal neighbors
are allowed. Elements are compared numerically when both are numbers,
otherwise as strings; arrays of objects are not orderable and fail the rule.

```cue
// Ascending order
expr: match: {
    path:   "spec.priorities"
    sorted: "asc"
}

// Descending order
expr: match: {
    path:   "spec.versions"
    sorted: "desc"
}
```

**Use Cases:**
- Priority queues must be ordered
- Version lists in descending order (newest first)

##### containsAll

Validates array contains all required values (superset check).

```cue
expr: match: {
    path: "spec.regions"
    containsAll: ["us-east-1", "eu-west-1"]
}
```

**Use Cases:**
- DR compliance: must deploy to all required regions
- Must include all mandatory labels
- Must have all required capabilities

##### subsetOf

Validates all array values are from an approved list (subset check). An
empty array passes.

```cue
expr: match: {
    path: "spec.zones"
    subsetOf: ["zone-a", "zone-b", "zone-c", "zone-d"]
}
```

**Use Cases:**
- Selected zones must be from approved list
- Requested permissions must be from allowed set
- Chosen options must be valid

#### Advanced Set Test Data

- Pass: `testdata/condition-operators/set-advanced-pass.json`
- Fail: `testdata/condition-operators/set-advanced-fail.json`

The `condition-operators` namespace contains several wildcard-target
policies, so evaluate these fixtures against the `set-advanced` policy
specifically with `-p`:

**CLI:**
```bash
# Should ALLOW (unique ports and names, sorted priorities, required regions, approved zones)
garmr eval --input testdata/condition-operators/set-advanced-pass.json -n condition-operators -p set-advanced

# Should DENY (duplicate ports and names, unsorted priorities, missing region, invalid zone)
garmr eval --input testdata/condition-operators/set-advanced-fail.json -n condition-operators -p set-advanced
```

**curl:**
```bash
# Test unique ports - should DENY (duplicate port 80)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "kind": "test-set-advanced",
      "spec": {
        "ports": [80, 443, 80],
        "containers": [{"name": "app"}],
        "priorities": [1, 2, 3],
        "regions": ["us-east-1", "eu-west-1"],
        "zones": ["zone-a"]
      }
    },
    "namespace": "condition-operators",
    "policies": ["set-advanced"]
  }'
```

---

### Logical Operators

Boolean logic: `all` (AND), `any` (OR), `not` (NOT).

**Policy:** `example-policies/condition-operators/logical.cue`

```cue
// AND - all conditions must pass
expr: {
    all: [
        {match: {path: "name", exists: true}},
        {match: {path: "version", exists: true}},
        {match: {path: "environment", exists: true}},
    ]
}

// OR - at least one must pass
expr: {
    any: [
        {match: {path: "contact.email", exists: true}},
        {match: {path: "contact.phone", exists: true}},
        {match: {path: "contact.slack", exists: true}},
    ]
}

// NOT - negates condition
expr: {
    not: {
        all: [
            {match: {path: "environment", equals: "production"}},
            {match: {path: "debug", equals: true}},
        ]
    }
}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "test-logical", "name": "app", "version": "1.0.0", "environment": "production", "debug": false, "contact": {"email": "team@example.com"}}' -n condition-operators

# Should DENY (missing version, no contact, debug in prod)
garmr eval -d '{"kind": "test-logical", "name": "app", "environment": "production", "debug": true}' -n condition-operators
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-logical", "name": "app", "version": "1.0.0", "environment": "production", "debug": false, "contact": {"email": "team@example.com"}}, "namespace": "condition-operators"}'
```

---

## Advanced Operators

Note: the example policies in the `advanced-operators` namespace mostly target all kinds (`*`), so an evaluation against that namespace runs every policy in it — expect results from rules beyond the operator being illustrated. Rules whose fields are missing from the input fail closed.

### forEach

Iterates over arrays and validates each element.

**Policy:** `example-policies/advanced-operators/foreach.cue`

```cue
expr: {
    forEach: {
        path: "spec.containers"
        as:   "container"
        condition: {
            all: [
                {match: {path: "container.resources.limits.memory", exists: true}},
                {match: {path: "container.resources.limits.cpu", exists: true}},
            ]
        }
    }
}
```

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `path` | string | JSONPath to array |
| `as` | string | Variable name for current item |
| `mode` | string | `all` (default) or `any` |
| `allowEmpty` | bool | Pass if array is empty |
| `condition` | object | Condition to evaluate per item |

**CLI:**
```bash
# All containers have limits - forEach rules FE-001 pass
garmr eval -d '{"kind": "Pod", "spec": {"containers": [{"name": "app", "image": "registry.corp.example.com/app:v1", "resources": {"cpuLimit": "500m", "memoryLimit": "512Mi"}}]}}' -n advanced-operators

# Container missing limits - forEach rules fail
garmr eval -d '{"kind": "Pod", "spec": {"containers": [{"name": "app", "image": "registry.corp.example.com/app:v1"}]}}' -n advanced-operators
```

---

### length

Validates string or array length.

**Policy:** `example-policies/advanced-operators/length.cue`

```cue
expr: match: {
    path: "metadata.name"
    length: {min: 3, max: 63}
}

expr: match: {
    path: "tags"
    length: {greaterThanOrEqual: 1}
}

expr: match: {
    path: "description"
    length: {lessThanOrEqual: 500}
}
```

**Operators:** `equals`, `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`, `min`, `max`

**CLI:**
```bash
# Name within limits, at least one tag - length rules pass
garmr eval -d '{"kind": "test-length", "metadata": {"name": "web-api", "tags": ["prod"]}}' -n advanced-operators

# Length violations (name too short, no tags)
garmr eval -d '{"kind": "test-length", "metadata": {"name": "ab", "tags": []}}' -n advanced-operators
```

---

### semver

Compares semantic versions.

**Policy:** `example-policies/advanced-operators/semver.cue`

```cue
expr: match: {
    path: "version"
    semver: {greaterThanOrEqual: "1.0.0"}
}

expr: match: {
    path: "spec.apiVersion"
    semver: {constraint: "^2.0.0"}  // 2.x compatible
}

expr: match: {
    path: "version"
    semver: {lessThan: "3.0.0"}
}
```

**Operators:** `equals`, `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`, `constraint`

**Constraints:**
- `^2.0.0` - Same major version (2.x.x)
- `~1.2.0` - Same minor version (1.2.x)
- `>=1.0.0,<2.0.0` - Range

**CLI:**
```bash
# Version 2.1.5 satisfies >= 2.0.0 - semver rules pass
garmr eval -d '{"kind": "test-semver", "spec": {"version": "2.1.5"}}' -n advanced-operators

# Version 0.9.0 fails >= 2.0.0 - semver rules fail
garmr eval -d '{"kind": "test-semver", "spec": {"version": "0.9.0"}}' -n advanced-operators
```

Invalid semver values fail the rule closed (with a diagnostic message) — a malformed version string never parses as `0.0.0`.

---

### datetime

Validates dates and expiration.

**Policy:** `example-policies/advanced-operators/datetime.cue`

```cue
expr: match: {
    path: "expiresAt"
    datetime: {notExpired: true}
}

expr: match: {
    path: "expiresAt"
    datetime: {expiresAfterDays: 30}
}

expr: match: {
    path: "createdAt"
    datetime: {after: "2024-01-01T00:00:00Z"}
}
```

**Operators:**
- `after`, `before`, `afterOrEqual`, `beforeOrEqual` - Compare to date
- `withinDays`, `withinHours` - Within time window
- `expiresAfterDays` - Must be valid for N days
- `notExpired` - Must be in the future

**Supported Formats:** RFC3339, ISO8601, date only (YYYY-MM-DD), `now`

Invalid datetime values fail the rule closed with a diagnostic message.

**CLI:**
```bash
# Certificate not yet expired - datetime rules pass
garmr eval -d '{"kind": "test-datetime", "spec": {"certificate": {"notAfter": "2030-01-01T00:00:00Z"}}}' -n advanced-operators

# Certificate expired - datetime rules fail
garmr eval -d '{"kind": "test-datetime", "spec": {"certificate": {"notAfter": "2024-01-01T00:00:00Z"}}}' -n advanced-operators
```

---

### compare (Cross-Field)

Compares two fields from the input.

**Policy:** `example-policies/advanced-operators/compare.cue`

```cue
expr: compare: {
    left: path:  "spec.minReplicas"
    op:          "<="
    right: path: "spec.maxReplicas"
}

expr: compare: {
    left: path:  "spec.resources.requests.memory"
    op:          "<="
    right: path: "spec.resources.limits.memory"
}

expr: compare: {
    left: path:  "schedule.startDate"
    op:          "before"
    right: path: "schedule.endDate"
}
```

**Operators:**
- Numeric: `==`, `!=`, `>`, `>=`, `<`, `<=`
- Semver: `semverGt`, `semverGte`, `semverLt`, `semverLte`, `semverEq`
- Datetime: `after`, `before`, `afterOrEqual`, `beforeOrEqual`

Non-numeric operands to numeric comparisons, and unknown compare operators, fail the rule closed with a diagnostic message.

**Test Data:**
- Fail: `testdata/advanced-operators/compare-fail.yaml` (minReplicas > maxReplicas)

**CLI:**
```bash
# maxReplicas > minReplicas - compare rule CMP-101 passes
garmr eval -d '{"kind": "test-compare", "spec": {"autoscaling": {"minReplicas": 2, "maxReplicas": 10}}}' -n advanced-operators

# Failing input from the repo test data
garmr eval --input testdata/advanced-operators/compare-fail.yaml -n advanced-operators
```

**curl:**
```bash
# Should DENY with violation
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-compare", "spec": {"minReplicas": 10, "maxReplicas": 5}}, "namespace": "advanced-operators"}'
```

---

## Policy Structure

Complete policy structure:

```cue
myPolicy: {
    apiVersion: "policy.garmr.io/v1"
    kind:       "Policy"
    metadata: {
        name:        "my-policy"
        namespace:   "my-namespace"
        description: "Policy description"
        labels: {
            "team": "platform"
        }
    }
    spec: {
        description: "Detailed description"
        target: {
            resources: ["deployment", "pod"]  // or ["*"] for all
        }
        rules: [
            {
                id:          "RULE-001"
                description: "Rule description"
                severity:    "high"  // critical, high, medium, low, info
                expr: {
                    // condition expression
                }
                message: "Failure message"
            }
        ]
        enforcement: {
            action: "deny"  // deny, warn, audit
        }
    }
}
```

---

## Running Tests

```bash
# Start server
make run

# Evaluate the provided operator test inputs
for f in testdata/advanced-operators/*; do
  echo "=== $f ==="
  garmr eval --input "$f" -n advanced-operators -o json | jq '{decision, violations: [.results[] | select(.passed==false) | .rule_id]}'
done

# Or run the policies' own test suites locally (no server needed)
garmr test ./example-policies --recursive
```
