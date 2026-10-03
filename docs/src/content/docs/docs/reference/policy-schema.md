---
title: "Policy Schema Reference"
description: "Complete reference for Garmr condition operators"
sidebar:
  order: 0
  label: "Policy Schema"
---

Complete reference for Garmr condition operators with CLI and API examples.
The schema itself is [`schemas/policy.cue`](https://github.com/infrashift/garmr/blob/main/schemas/policy.cue);
every policy is unified with it when it loads.

## Overview

A rule's `expr` is an **expression**, and an expression sets **exactly one**
of these operators:

| Operator | Checks |
|----------|--------|
| `match` | A field at `path`: presence, equality, comparison, strings, sets, `length`, `semver`, `datetime` |
| `compare` | Two values (input paths, literals, or builtin results) against each other |
| `forEach` | Every element (or, with `mode: "any"`, at least one) of a list |
| `func` | The result of a builtin function |
| `all` / `any` / `not` | Combine expressions: AND, OR, NOT |

Expressions are typed by the schema, so a misspelled operator (`mach:`,
`greaterThen:`) or two operators in one expression is rejected **when the
policy loads** — at server startup or reload, by `garmr validate`, and by
`/v1/validate` — never discovered at evaluation time. Combine checks with
`all` / `any`.

Policies are compiled once at load into Go evaluation trees (regular
expressions, versions, dates and value sets are parsed up front), so an
evaluation never touches CUE.

### Paths

Paths are dot-separated field names into the input: `spec.containers`.

- Quote a key that contains dots or other punctuation:
  `metadata.labels."app.kubernetes.io/name"`.
- Index a list with `[N]`: `spec.containers[0].image`.
- Project a list with `[*]`: `spec.containers[*].cpu` is the list of every
  container's `cpu`, ready for `sum`, `len`, `unique`, `containsAll` and the
  other list operators, or for `forEach`. A container without the field
  contributes `null`, so `sum` fails rather than under-counting. Nested
  projections flatten (`spec.containers[*].ports[*].containerPort`); a
  container with no `ports` list contributes nothing.
- Keys such as `host-network` or `_private` work as written.
- Inside `forEach`, a path that starts with the alias (`container.image`)
  reads the current element, and `_index` is its position. The alias shadows
  an input field of the same name.

### Evaluation semantics

- **Equality is strict and JSON-typed.** Numbers compare by value (`1` equals
  `1.0`); every other pair must have the same type, so `"1"` does not equal
  `1` and `"true"` does not equal `true`. This applies to `equals`, `in`,
  `notIn`, the set operators, and `compare` `==` / `!=`.
- **A missing field fails the check.** So `not: {match: {path:
  "securityContext.privileged", equals: true}}` passes when the field is
  absent.
- **An operand of the wrong type is an evaluation error**, not a failure: a
  string where a number is needed, an unparseable semver or datetime, a list
  operator on a non-list, a builtin that returns an error. An error fails
  the rule **even under `not` or `any`**, and the violation message says the
  rule could not be evaluated.

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

A `match` block may specify more than one operator alongside `path`; every specified operator must pass (AND semantics). The same holds inside the `length`, `semver`, and `datetime` blocks, so `datetime: {after: X, before: Y}` is a range check and `semver: {greaterThanOrEqual: "1.0.0", lessThan: "2.0.0"}` bounds a version. When several operators fail, the violation message reports each unmet check.

### exists

Validates field presence or absence.

**Policy:** `example-policies/condition-operators/exists.cue`

```cue
expr: match: {
    path:   "requiredField"
    exists: true
}

expr: match: {
    path:   "deprecatedField"
    exists: false
}
```

`exists: true` passes when the field is present and not null; `exists:
false` passes when it is absent or null.

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

Set membership and array validation: `in`, `notIn`, `unique`, `uniqueBy`, `sorted`, `containsAll`, `containsAny`, `subsetOf`.

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

Array validation operators. Element equality is the strict equality above
(`1` and `1.0` are the same value; `"1"` and `1` are not), and a non-array
value at the path is an evaluation error.

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
are allowed. Elements must be all numbers or all strings; anything else
(objects, mixed kinds) is not orderable and fails the rule.

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

##### containsAny

Validates array contains at least one of the listed values.

```cue
expr: match: {
    path: "spec.logging.formats"
    containsAny: ["json", "structured"]
}
```

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
| `path` | string | Path to the list |
| `as` | string | Name the condition uses for the current element (default `item`) |
| `mode` | string | `all` (default): every element must pass; `any`: at least one |
| `allowEmpty` | bool | Whether an empty list passes (default `true`) |
| `where` | expression | Only elements for which this holds are checked (and counted) |
| `condition` | expression | Expression evaluated per element |

Inside `condition`, paths starting with the alias read the element and
`_index` is its position; other paths read the input. `forEach` nests, and
an inner condition can refer to both aliases. A missing list fails; a
non-list value is an evaluation error. The evaluation deadline is checked on
every element.

**Filtering.** `where` selects the elements the condition applies to; the
others are skipped entirely. `allowEmpty`, `mode: "any"` and `count` apply
to the selected elements, so `allowEmpty: false` means "at least one element
must match `where`".

```cue
// Application containers (not sidecars) must not run privileged.
expr: forEach: {
    path:  "spec.containers"
    as:    "c"
    where: not: match: {path: "c.name", hasPrefix: "istio-"}
    condition: match: {path: "c.securityContext.privileged", equals: false}
}
```

**Counting.** `count` checks how many elements pass instead of requiring
all or any of them. It takes the same operators as `length` and replaces
`mode` and `allowEmpty` (an empty list counts 0). The count is available to
the message as `{{.count}}`.

```cue
// At most one container may run privileged.
expr: forEach: {
    path: "spec.containers"
    as:   "c"
    count: lessThanOrEqual: 1
    condition: match: {path: "c.securityContext.privileged", equals: true}
}
message: "{{.count}} containers run privileged; at most 1 may"
```

If any element cannot be evaluated, the count is unknown and the rule fails
with an evaluation error.

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
    length: {greaterThanOrEqual: 3, lessThanOrEqual: 63}
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

**Operators:** `equals`, `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`

Lists count elements; strings count characters (not bytes). The length is
available to the rule's `message` as `{{.length}}`.

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
- `withinDays`, `withinHours` - Within N days/hours of now, in either direction
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

Each side is a value: exactly one of `path` (an input field; a missing
field resolves to null), `literal`, or `func` (a builtin call, see below).

**Operators:**
- Equality: `==`, `!=` (strict, as above)
- Ordering: `>`, `>=`, `<`, `<=` — two numbers, or two strings (lexical)
- Membership: `in`, `notIn` — the right side must be a list
- Strings: `contains` (a list containing the element, or a substring),
  `hasPrefix`, `hasSuffix`, `matches` (RE2)
- Containment: `subsetOf` — every key/value of the left object is in the
  right object (a label selector within a pod's labels), or every element of
  the left list is in the right list
- Semver: `semverGt`, `semverGte`, `semverLt`, `semverLte`, `semverEq`
- Datetime: `after`, `before`, `afterOrEqual`, `beforeOrEqual`

Operands of the wrong type for an operator are an evaluation error. An
unknown operator is rejected when the policy loads.

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

#### Joins

Nested `forEach` with `compare` across the two aliases joins two lists;
`where` picks the matching pairs:

```cue
// Each Service must select the pods of the Deployment with the same name.
expr: forEach: {
    path: "services", as: "s"
    condition: forEach: {
        path:  "deployments", as: "d"
        where: compare: {left: {path: "d.metadata.name"}, op: "==", right: {path: "s.metadata.name"}}
        condition: compare: {left: {path: "s.spec.selector"}, op: "subsetOf", right: {path: "d.spec.template.metadata.labels"}}
    }
}
message: "service {{s.metadata.name}} does not select the pods of deployment {{d.metadata.name}}"
```

**Policy:** `example-policies/advanced-operators/aggregate.cue` (with the
projection, counting and message examples).

---

### func (Builtins)

Calls a builtin. Arguments are values, like `compare` operands. Without
`expect`, the result must be truthy (not `false`, `0`, `""`, `[]`, `{}` or
null); with `expect`, it must equal it. `bind` names the result for the
rule's `message` template.

**Policy:** `example-policies/builtins/func-calls.cue`

```cue
expr: "func": {
    name: "cidrContains"
    args: [{literal: "10.244.0.0/16"}, {path: "spec.podIP"}]
    expect: true
}

expr: compare: {
    left: {func: {name: "unitsParse", args: [{path: "spec.resources.requests.cpu"}]}}
    op:    ">="
    right: {func: {name: "unitsParse", args: [{literal: "100m"}]}}
}
```

**Builtins:** `len`, `sum`, `min`, `max`, `avg`, `lower`, `upper`, `trim`,
`trimPrefix`, `trimSuffix`, `split`, `join`, `matches` (string, pattern),
`format`, `base64Decode`, `base64Encode`, `now`, `duration`, `parseTime`,
`typeOf`, `isType`, `hasKey`, `keys`, `values`, `lookup`, `cidrContains`,
`cidrOverlap`, `ipVersion`, `unitsParse`, `flatten`, `unique`, `sort`,
`filter`. An unknown name is rejected when the policy loads; a builtin that
returns an error is an evaluation error.

---

## Rule Applicability (`when`)

A rule with `when` applies only to inputs for which the `when` expression
holds; for any other input it passes as not applicable.

```cue
{
    id:          "REP-001"
    description: "Production deployments need at least 2 replicas"
    severity:    "high"
    when: match: {path: "metadata.labels.env", equals: "prod"}
    expr: match: {path: "spec.replicas", greaterThanOrEqual: 2}
}
```

A missing field makes `when` fail like any check, so the rule above does not
apply to an input with no `env` label. If `when` itself cannot be evaluated
(an operand of the wrong type), the rule fails with an evaluation error: a
check is never skipped because its precondition broke. The same holds for a
`forEach` `where`.

Use `when` to scope a rule by the input's content; use `target` to scope a
whole policy by kind, names, namespaces and labels.

---

## Messages

A rule's `message` is a template:

| Placeholder | Value |
|-------------|-------|
| `{{.name}}` | A binding: `length`, `version`, `datetime`, `count`, or a `func` `bind` name |
| `{{metadata.name}}` | A field of the input |
| `{{c.name}}` | A field of the element a `forEach` alias (`c`) was bound to |
| `{{_index}}` | The position of the innermost failing element |

A message that refers to a `forEach` alias is rendered **once per failing
element** and the renderings are joined, so

```cue
message: "container {{c.name}} exposes undeclared port {{p.containerPort}}"
```

reports `container debug exposes undeclared port 9229; container debug
exposes undeclared port 6060`. Elements visited inside a branch that
ultimately passed (an `any` or `not`) are not reported. A placeholder that
does not resolve is left as written. A malformed placeholder is a load
error.

---

## Load-Time Validation

A policy that fails any of these checks is rejected when it loads (startup
fails, a reload keeps the previous set, `garmr validate` and `/v1/validate`
report it):

- The document does not unify with the schema (unknown fields, wrong types).
- An expression sets no operator, or more than one.
- An operand cannot be compiled: a malformed path, an invalid regular
  expression, semver or datetime literal, an unknown builtin or compare
  operator, or a malformed message placeholder.
- A `forEach` sets `count` together with `mode` or `allowEmpty`.
- Two rules in the policy share an `id`.
- An exception `match` selects everything (it would disable the policy), or
  its `expiry` is not an RFC3339 timestamp.
- `evaluation.timeout` is not a positive Go duration (`"250ms"`, `"30s"`).
- Two policy documents declare the same `namespace/name`.

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
            // A string is a kind in any API group; a struct is a selector:
            // {kind, apiGroup, names, namespaces, labels, annotations}.
            // apiGroup matches the group of the input's apiVersion
            // ("apps" for "apps/v1"; "" is the core group).
            resources: ["Deployment", {kind: "Pod", apiGroup: ""}]  // or ["*"]
        }
        rules: [
            {
                id:          "RULE-001"
                description: "Rule description"
                severity:    "high"  // critical, high, medium, low, info
                when: {
                    // optional: the rule applies only when this holds
                }
                expr: {
                    // condition expression
                }
                message: "Failure message"
            }
        ]
        enforcement: {
            action: "deny"  // deny, warn, audit
            exceptions: [{
                name:   "legacy-batch"
                reason: "migrating in Q3"
                match: {names: ["batch-*"]}
                expiry: "2026-12-31T00:00:00Z"
            }]
        }
        evaluation: {
            order:    "priority"  // priority, severity, definition, priority-then-severity
            failFast: false
            timeout:  "250ms"
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
