# Policy Schema Reference

Complete reference for Garmr condition operators with CLI and API examples.

## Overview

Garmr supports 25+ condition operators organized into:

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
q eval --input deployment.yaml -n security
q eval --input deployment.json -n security

# Explicit format flag
q eval --input deployment.txt --format yaml -n security

# Stdin with format hint
cat deployment.yaml | q eval --input - --format yaml -n security
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
| `warn` | Log warning but allow | 2 (with `--fail-on-warn`) |
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

**Test Data (JSON):**
- Pass: `test-data/condition-operators/exists-pass.json`
- Fail: `test-data/condition-operators/exists-fail.json`

**Test Data (YAML):**
- Pass: `test-data/condition-operators/exists-pass.yaml`
- Fail: `test-data/condition-operators/exists-fail.yaml`

**CLI (JSON):**
```bash
# Should ALLOW (all required fields present)
q eval --input test-data/condition-operators/exists-pass.json -n condition-operators

# Should DENY (missing requiredField)
q eval --input test-data/condition-operators/exists-fail.json -n condition-operators
```

**CLI (YAML):**
```bash
# Should ALLOW (auto-detects YAML from extension)
q eval --input test-data/condition-operators/exists-pass.yaml -n condition-operators

# Explicit format flag
q eval --input test-data/condition-operators/exists-pass.yaml --format yaml -n condition-operators
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

**Test Data:**
- Pass: `test-data/condition-operators/equals-pass.json`
- Fail: `test-data/condition-operators/equals-fail.json`

**CLI:**
```bash
# Should ALLOW
q eval --input test-data/condition-operators/equals-pass.json -n condition-operators

# Should DENY
q eval --input test-data/condition-operators/equals-fail.json -n condition-operators
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

**Test Data:**
- Pass: `test-data/condition-operators/comparison-pass.json`
- Fail: `test-data/condition-operators/comparison-fail.json`

**CLI:**
```bash
# Should ALLOW (replicas=3, memory=2048, cpu=4)
q eval --input test-data/condition-operators/comparison-pass.json -n condition-operators

# Should DENY (replicas=1, memory=8192, cpu=16)
q eval --input test-data/condition-operators/comparison-fail.json -n condition-operators
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

**Test Data:**
- Pass: `test-data/condition-operators/string-pass.json`
- Fail: `test-data/condition-operators/string-fail.json`

**CLI:**
```bash
# Should ALLOW
q eval --input test-data/condition-operators/string-pass.json -n condition-operators

# Should DENY (wrong registry, :latest tag, invalid name)
q eval --input test-data/condition-operators/string-fail.json -n condition-operators
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

Set membership and validation: `in`, `notIn`, `unique`, `uniqueBy`, `sorted`, `containsAll`, `subsetOf`.

**Policy:** `example-policies/condition-operators/set.cue`

#### Basic Set Membership

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

**Test Data:**
- Pass: `test-data/condition-operators/set-pass.json`
- Fail: `test-data/condition-operators/set-fail.json`

**CLI:**
```bash
# Should ALLOW (production, us-east-1, premium)
q eval --input test-data/condition-operators/set-pass.json -n condition-operators

# Should DENY (test environment, restricted region)
q eval --input test-data/condition-operators/set-fail.json -n condition-operators
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-set", "environment": "production", "region": "us-east-1", "tier": "premium"}, "namespace": "condition-operators"}'
```

#### Advanced Set Operators

##### unique / uniqueBy

Validates no duplicate values in arrays.

```cue
// Simple array - no duplicate values
expr: match: {
    path:   "spec.ports"
    unique: true
}

// Array of objects - no duplicates by field
expr: match: {
    path:     "spec.containers"
    uniqueBy: "name"
}
```

**Use Cases:**
- No duplicate port numbers in a service
- No duplicate container names in a pod
- No duplicate environment variable names

##### sorted

Validates array is in sorted order.

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

Validates all array values are from an approved list (subset check).

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

- Pass: `test-data/condition-operators/set-advanced-pass.json`
- Fail: `test-data/condition-operators/set-advanced-fail.json`

**CLI:**
```bash
# Should ALLOW (unique ports, unique container names, sorted priorities, required regions, valid zones)
q eval --input test-data/condition-operators/set-advanced-pass.json -n condition-operators

# Should DENY (duplicate ports, duplicate container names, unsorted, missing regions, invalid zones)
q eval --input test-data/condition-operators/set-advanced-fail.json -n condition-operators
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
    "namespace": "condition-operators"
  }'

# Test containsAll - should DENY (missing eu-west-1)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "kind": "test-set-advanced",
      "spec": {
        "ports": [80, 443],
        "containers": [{"name": "app"}],
        "priorities": [1, 2],
        "regions": ["us-west-2"],
        "zones": ["zone-a"]
      }
    },
    "namespace": "condition-operators"
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

**Test Data:**
- Pass: `test-data/condition-operators/logical-pass.json`
- Fail: `test-data/condition-operators/logical-fail.json`

**CLI:**
```bash
# Should ALLOW
q eval --input test-data/condition-operators/logical-pass.json -n condition-operators

# Should DENY (missing version, no contact, debug in prod)
q eval --input test-data/condition-operators/logical-fail.json -n condition-operators
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

**Test Data:**
- Pass: `test-data/advanced-operators/foreach-pass.json`
- Fail: `test-data/advanced-operators/foreach-fail.json`

**CLI:**
```bash
# Should ALLOW (all containers have limits, approved registries, not privileged)
q eval --input test-data/advanced-operators/foreach-pass.json -n advanced-operators

# Should DENY (missing limits, untrusted registry, privileged)
q eval --input test-data/advanced-operators/foreach-fail.json -n advanced-operators
```

**curl:**
```bash
# Should DENY (violations)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d @test-data/advanced-operators/foreach-fail.json \
  | jq '.decision, .results[].message'
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

**Test Data:**
- Pass: `test-data/advanced-operators/length-pass.json`
- Fail: `test-data/advanced-operators/length-fail.json`

**CLI:**
```bash
# Should WARN (enforcement: warn) - passes with warnings
q eval --input test-data/advanced-operators/length-pass.json -n advanced-operators

# Should WARN with violations (name too short, no tags)
q eval --input test-data/advanced-operators/length-fail.json -n advanced-operators
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

**Test Data:**
- Pass: `test-data/advanced-operators/semver-pass.json` (version 2.1.5, apiVersion 2.3.0)
- Fail: `test-data/advanced-operators/semver-fail.json` (version 0.9.0, apiVersion 1.5.0)

**CLI:**
```bash
# Should ALLOW
q eval --input test-data/advanced-operators/semver-pass.json -n advanced-operators

# Should DENY (version < 1.0.0, apiVersion not 2.x)
q eval --input test-data/advanced-operators/semver-fail.json -n advanced-operators
```

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

**Test Data:**
- Pass: `test-data/advanced-operators/datetime-pass.json` (expires 2026)
- Fail: `test-data/advanced-operators/datetime-fail.json` (expired 2024)

**CLI:**
```bash
# Should ALLOW (certificate valid until 2026)
q eval --input test-data/advanced-operators/datetime-pass.json -n advanced-operators

# Should DENY (certificate expired)
q eval --input test-data/advanced-operators/datetime-fail.json -n advanced-operators
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

**Test Data:**
- Pass: `test-data/advanced-operators/compare-pass.json` (minReplicas < maxReplicas)
- Fail: `test-data/advanced-operators/compare-fail.json` (minReplicas > maxReplicas)

**CLI:**
```bash
# Should ALLOW (minReplicas=2, maxReplicas=10)
q eval --input test-data/advanced-operators/compare-pass.json -n advanced-operators

# Should DENY (minReplicas=10, maxReplicas=5)
q eval --input test-data/advanced-operators/compare-fail.json -n advanced-operators
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

# Test all condition operators
for f in test-data/condition-operators/*.json; do
  echo "=== $f ==="
  q eval --input "$f" -n condition-operators -o json | jq '{decision, violations: [.results[] | select(.passed==false) | .rule_id]}'
done

# Test all advanced operators
for f in test-data/advanced-operators/*.json; do
  echo "=== $f ==="
  q eval --input "$f" -n advanced-operators -o json | jq '{decision, violations: [.results[] | select(.passed==false) | .rule_id]}'
done
```