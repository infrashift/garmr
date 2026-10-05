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
  operator on a non-list, a builtin that returns an error. An error never
  turns into a pass:
  - `not` of an error is an error.
  - `any` (and `forEach` `mode: "any"`) passes if some branch passes;
    otherwise an error in any branch makes the result an error.
  - `all` (and `forEach` in its default mode) fails if some branch fails;
    otherwise an error in any branch makes the result an error.

  A rule whose result is an error fails, and its violation message says the
  rule could not be evaluated ("Rule SV-001 could not be evaluated: …").

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

The request's decision is the strictest across the matched policies:
`deny` beats `warn` beats `allow`. With `enforcement.dryRun: true`, a
policy reports its violations (each message prefixed `[DRY RUN]`) but its
`deny` is lowered to `warn`. A policy that runs out of time denies
regardless of `action` or `dryRun`.

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

Each section below quotes the rules of an example policy in
`example-policies/` (abbreviated to `id` and `expr`) and evaluates them.
Most example policies target every kind (`*`), so an evaluation against a
whole namespace runs all of them and almost any input is denied by one or
another. The examples therefore name the policies they exercise: `-p`
(repeatable or comma-separated) on the CLI, `"policies"` in the REST body.
A policy is named `namespace/name`, or by bare name together with the
namespace (`-n` / `"namespace"`), which is the form used below.

A `match` block may specify more than one operator alongside `path`; every specified operator must pass (AND semantics). The same holds inside the `length`, `semver`, and `datetime` blocks, so `datetime: {after: X, before: Y}` is a range check and `semver: {greaterThanOrEqual: "1.0.0", lessThan: "2.0.0"}` bounds a version. When several operators fail, the violation message reports each unmet check.

### exists

Validates field presence or absence.

**Policies:** `exists-operator` and `absent-operator` in
`example-policies/condition-operators/exists.cue`

```cue
// exists-operator (targets kind "test-exists")
{id: "EXISTS-001", expr: match: {path: "requiredField", exists: true}}
{id: "EXISTS-002", expr: match: {path: "metadata.name", exists: true}}

// absent-operator (targets kind "test-absent")
{id: "ABSENT-001", expr: match: {path: "deprecatedField", exists: false}}
{id: "ABSENT-002", expr: match: {path: "config.legacy", exists: false}}
```

`exists: true` passes when the field is present and not null; `exists:
false` passes when it is absent or null.

**CLI:**
```bash
# Should ALLOW (required field present)
garmr eval -d '{"kind": "test-exists", "requiredField": "present", "metadata": {"name": "test"}}' -n condition-operators -p exists-operator

# Should DENY (missing requiredField)
garmr eval -d '{"kind": "test-exists", "metadata": {"name": "test"}}' -n condition-operators -p exists-operator
```

**curl (JSON):**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "test-exists", "requiredField": "present", "metadata": {"name": "test"}}, "namespace": "condition-operators", "policies": ["exists-operator"]}'
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
policies: [exists-operator]
'
```

---

### equals

Validates exact field value (string, number, or boolean). Equality is
strict: `"true"` does not equal `true`.

**Policies:** `equals-string`, `equals-numeric` (`action: warn`) and
`equals-boolean` in `example-policies/condition-operators/equals.cue`

```cue
// equals-string
{id: "EQ-001", expr: match: {path: "environment", equals: "production"}}
{id: "EQ-002", expr: match: {path: "metadata.region", equals: "us-east-1"}}
// equals-numeric
{id: "EQ-003", expr: match: {path: "spec.replicas", equals: 3}}
// equals-boolean
{id: "EQ-004", expr: match: {path: "spec.tls.enabled", equals: true}}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "Service", "environment": "production", "metadata": {"region": "us-east-1"}, "spec": {"replicas": 3, "tls": {"enabled": true}}}' -n condition-operators -p equals-string,equals-numeric,equals-boolean

# Should WARN (replicas 5 fails EQ-003, whose policy only warns)
garmr eval -d '{"kind": "Service", "environment": "production", "metadata": {"region": "us-east-1"}, "spec": {"replicas": 5, "tls": {"enabled": true}}}' -n condition-operators -p equals-string,equals-numeric,equals-boolean

# Should DENY (the string "true" is not the boolean true)
garmr eval -d '{"kind": "Service", "environment": "production", "metadata": {"region": "us-east-1"}, "spec": {"replicas": 3, "tls": {"enabled": "true"}}}' -n condition-operators -p equals-string,equals-numeric,equals-boolean
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "Service", "environment": "production", "metadata": {"region": "us-east-1"}, "spec": {"replicas": 3, "tls": {"enabled": true}}}, "namespace": "condition-operators", "policies": ["equals-string", "equals-numeric", "equals-boolean"]}'
```

---

### Comparison Operators

Numeric comparisons: `greaterThan`, `greaterThanOrEqual`, `lessThan`,
`lessThanOrEqual`. A non-numeric value at the path is an evaluation error.

**Policy:** `numeric-comparison` in
`example-policies/condition-operators/comparison.cue`

```cue
{id: "CMP-001", expr: match: {path: "spec.replicas", greaterThanOrEqual: 2}}
{id: "CMP-002", expr: match: {path: "spec.replicas", lessThanOrEqual: 10}}
{id: "CMP-003", expr: match: {path: "spec.resources.cpu", greaterThan: 0}}
{id: "CMP-004", expr: match: {path: "spec.resources.memoryMB", lessThan: 8192}}
```

**CLI:**
```bash
# Should ALLOW (replicas=3, cpu=2, memory=4096)
garmr eval -d '{"kind": "Deployment", "spec": {"replicas": 3, "resources": {"cpu": 2, "memoryMB": 4096}}}' -n condition-operators -p numeric-comparison

# Should DENY (replicas=1 fails CMP-001, memory=8192 fails CMP-004)
garmr eval -d '{"kind": "Deployment", "spec": {"replicas": 1, "resources": {"cpu": 2, "memoryMB": 8192}}}' -n condition-operators -p numeric-comparison
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "Deployment", "spec": {"replicas": 3, "resources": {"cpu": 2, "memoryMB": 4096}}}, "namespace": "condition-operators", "policies": ["numeric-comparison"]}'
```

---

### String Operators

String matching: `contains`, `hasPrefix`, `hasSuffix`, `pattern` (RE2,
compiled when the policy loads; at most 512 bytes). A non-string value at
the path is an evaluation error.

**Policy:** `string-matching` in
`example-policies/condition-operators/string.cue`

```cue
{id: "STR-001", expr: not: match: {path: "spec.image.tag", contains: "latest"}}
{id: "STR-002", expr: match: {path: "metadata.name", hasPrefix: "team-"}}
{id: "STR-003", expr: match: {path: "spec.ingress.hostname", hasSuffix: ".example.com"}}
{id: "STR-004", expr: match: {path: "metadata.labels.version", pattern: "^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9.]+)?$"}}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "Service", "metadata": {"name": "team-payments", "labels": {"version": "v1.4.2"}}, "spec": {"image": {"tag": "v1.4.2"}, "ingress": {"hostname": "payments.example.com"}}}' -n condition-operators -p string-matching

# Should DENY (tag contains "latest", name lacks the "team-" prefix)
garmr eval -d '{"kind": "Service", "metadata": {"name": "payments", "labels": {"version": "v1.4.2"}}, "spec": {"image": {"tag": "latest"}, "ingress": {"hostname": "payments.example.com"}}}' -n condition-operators -p string-matching
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "Service", "metadata": {"name": "team-payments", "labels": {"version": "v1.4.2"}}, "spec": {"image": {"tag": "v1.4.2"}, "ingress": {"hostname": "payments.example.com"}}}, "namespace": "condition-operators", "policies": ["string-matching"]}'
```

---

### Set Operators

Set membership and array validation: `in`, `notIn`, `unique`, `uniqueBy`, `sorted`, `containsAll`, `containsAny`, `subsetOf`.

**Policy:** `set-membership` in `example-policies/condition-operators/set.cue`

```cue
{id: "SET-001", expr: match: {path: "environment", in: ["development", "staging", "production"]}}
{id: "SET-002", expr: match: {path: "region", in: ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"]}}
{id: "SET-003", expr: match: {path: "spec.image.registry", notIn: ["docker.io", "quay.io", "public.ecr.aws"]}}
```

Like every check, `notIn` fails when the field is missing.

**CLI:**
```bash
# Should ALLOW (production, us-east-1, private registry)
garmr eval -d '{"kind": "Deployment", "environment": "production", "region": "us-east-1", "spec": {"image": {"registry": "registry.example.com"}}}' -n condition-operators -p set-membership

# Should DENY (unknown environment, public registry)
garmr eval -d '{"kind": "Deployment", "environment": "test", "region": "us-east-1", "spec": {"image": {"registry": "docker.io"}}}' -n condition-operators -p set-membership
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "Deployment", "environment": "production", "region": "us-east-1", "spec": {"image": {"registry": "registry.example.com"}}}, "namespace": "condition-operators", "policies": ["set-membership"]}'
```

#### Advanced Set Operators

Array validation operators. Element equality is the strict equality above
(`1` and `1.0` are the same value; `"1"` and `1` are not), and a non-array
value at the path is an evaluation error.

**Policy:** `set-advanced` in `example-policies/condition-operators/set.cue`
(targets `kind: "test-set-advanced"`)

```cue
{id: "SET-101", expr: match: {path: "spec.ports", unique: true}}
{id: "SET-102", expr: match: {path: "spec.containers", uniqueBy: "name"}}
{id: "SET-103", expr: match: {path: "spec.priorities", sorted: "asc"}}
{id: "SET-104", expr: match: {path: "spec.regions", containsAll: ["us-east-1", "eu-west-1"]}}
{id: "SET-105", expr: match: {path: "spec.zones", subsetOf: ["zone-a", "zone-b", "zone-c", "zone-d"]}}
```

| Operator | Passes when |
|----------|-------------|
| `unique: true` | The list has no duplicate values (`unique: false` places no constraint) |
| `uniqueBy: "<path>"` | No two elements share the value at that path (dot-notation paths supported); an element missing the field fails the rule |
| `sorted: "asc"` / `"desc"` | The list is in order; equal neighbours are allowed. Elements must be all numbers or all strings; anything else is not orderable and fails |
| `containsAll: [...]` | Every listed value is in the list (superset check) |
| `containsAny: [...]` | At least one listed value is in the list |
| `subsetOf: [...]` | Every element is one of the listed values; an empty list passes |

**Use Cases:** no duplicate ports or container names; ordered priority
lists; DR compliance (deployed to every required region); zones or
permissions chosen from an approved set.

**Test Data:**
- Pass: `testdata/condition-operators/set-advanced-pass.json`
- Fail: `testdata/condition-operators/set-advanced-fail.json`

**CLI:**
```bash
# Should ALLOW (unique ports and names, sorted priorities, required regions, approved zones)
garmr eval --input testdata/condition-operators/set-advanced-pass.json -n condition-operators -p set-advanced

# Should DENY (duplicate ports and names, unsorted priorities, missing region, invalid zone)
garmr eval --input testdata/condition-operators/set-advanced-fail.json -n condition-operators -p set-advanced
```

**curl:**
```bash
# Should DENY (duplicate port 80)
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

Boolean logic: `all` (AND), `any` (OR), `not` (NOT). See
[Evaluation semantics](#evaluation-semantics) for how they treat evaluation
errors.

**Policies:** `logical-all`, `logical-any`, `logical-not` and
`logical-nested` in `example-policies/condition-operators/logical.cue`

```cue
// AND - every condition must pass
{id: "LOG-001", expr: all: [
    {match: {path: "environment", equals: "production"}},
    {match: {path: "spec.replicas", greaterThanOrEqual: 2}},
    {match: {path: "spec.resources.cpuLimit", greaterThan: 0}},
    {match: {path: "spec.resources.memoryLimit", greaterThan: 0}},
]}

// OR - at least one must pass
{id: "LOG-002", expr: any: [
    {match: {path: "spec.auth.method", equals: "oauth2"}},
    {match: {path: "spec.auth.method", equals: "oidc"}},
    {match: {path: "spec.auth.method", equals: "mtls"}},
]}

// NOT - passes when the inner check fails (including when spec.debug is absent)
{id: "LOG-003", expr: not: match: {path: "spec.debug", equals: true}}

// Nested
{id: "LOG-004", expr: all: [
    {match: {path: "spec.tls.enabled", equals: true}},
    {any: [
        {match: {path: "spec.protocol", equals: "https"}},
        {match: {path: "spec.protocol", equals: "grpcs"}},
    ]},
    {not: match: {path: "spec.runAsRoot", equals: true}},
]}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "Service", "environment": "production", "spec": {"replicas": 3, "resources": {"cpuLimit": 2, "memoryLimit": 4096}, "auth": {"method": "oidc"}, "debug": false, "tls": {"enabled": true}, "protocol": "https", "runAsRoot": false}}' -n condition-operators -p logical-all,logical-any,logical-not,logical-nested

# Should DENY (unapproved auth method, debug on, plain http)
garmr eval -d '{"kind": "Service", "environment": "production", "spec": {"replicas": 3, "resources": {"cpuLimit": 2, "memoryLimit": 4096}, "auth": {"method": "basic"}, "debug": true, "tls": {"enabled": true}, "protocol": "http", "runAsRoot": false}}' -n condition-operators -p logical-all,logical-any,logical-not,logical-nested
```

**curl:**
```bash
# Should ALLOW
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "Service", "environment": "production", "spec": {"replicas": 3, "resources": {"cpuLimit": 2, "memoryLimit": 4096}, "auth": {"method": "oidc"}, "debug": false, "tls": {"enabled": true}, "protocol": "https", "runAsRoot": false}}, "namespace": "condition-operators", "policies": ["logical-all", "logical-any", "logical-not", "logical-nested"]}'
```

---

## Advanced Operators

As above, the examples name the policies they exercise, because most
policies in the `advanced-operators` namespace target every kind. Rules
whose fields are missing from the input fail closed.

### forEach

Iterates over arrays and validates each element.

**Policies:** `foreach-all`, `foreach-any` (`action: warn`) and
`foreach-nested` in `example-policies/advanced-operators/foreach.cue`

```cue
{id: "FE-001", expr: forEach: {
    path: "spec.containers"
    as:   "container"
    mode: "all"
    condition: all: [
        {match: {path: "container.resources.cpuLimit", exists: true}},
        {match: {path: "container.resources.memoryLimit", exists: true}},
    ]
}}
{id: "FE-002", expr: forEach: {
    path: "spec.containers", as: "c", mode: "all"
    condition: match: {path: "c.image", hasPrefix: "registry.example.com/"}
}}
{id: "FE-003", expr: forEach: {
    path: "spec.maintainers", as: "maintainer", mode: "any"
    condition: match: {path: "maintainer.role", equals: "admin"}
}}
```

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `path` | string | Path to the list |
| `as` | string | Name the condition uses for the current element (default `item`); must be an identifier (letters, digits, underscores, starting with a letter) |
| `condition` | expression | Expression evaluated per element (required) |
| `mode` | string | `all` (default): every element must pass; `any`: at least one |
| `allowEmpty` | bool | Whether an empty list passes (default `true`) |
| `where` | expression | Only elements for which this holds are checked (and counted) |
| `count` | length operators | Check how many elements pass instead of `mode`/`allowEmpty` (see below) |

Inside `condition`, paths starting with the alias read the element and
`_index` is its position; other paths read the input. Because of that, a
path whose first key is literally `_index` reads the position, not an input
field of that name, anywhere inside a `forEach`. `forEach` nests, and an
inner condition can refer to both aliases. A missing list fails; a non-list
value is an evaluation error. The evaluation deadline is checked on every
element.

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
`mode` and `allowEmpty` (setting both is a load error; an empty list counts
0). The count is available to the message as `{{.count}}`.

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
# Should ALLOW (limits set, approved registry, an admin maintainer, a named non-restricted port)
garmr eval -d '{"kind": "Pod", "spec": {"containers": [{"name": "app", "image": "registry.example.com/app:v1", "resources": {"cpuLimit": "500m", "memoryLimit": "512Mi"}}], "maintainers": [{"name": "ana", "role": "admin"}], "ports": [{"name": "http", "number": 8080}]}}' -n advanced-operators -p foreach-all,foreach-any,foreach-nested

# Should DENY (no limits, docker.io image, restricted port 22: FE-001, FE-002, FE-004)
garmr eval -d '{"kind": "Pod", "spec": {"containers": [{"name": "app", "image": "docker.io/app:v1"}], "maintainers": [{"name": "ana", "role": "admin"}], "ports": [{"name": "ssh", "number": 22}]}}' -n advanced-operators -p foreach-all,foreach-any,foreach-nested
```

#### Projections, counts and per-element messages

**Policy:** `aggregate-checks` in
`example-policies/advanced-operators/aggregate.cue` (targets `kind:
"test-aggregate"`) combines a `[*]` projection with `sum`, a counted
`forEach`, a nested `forEach` with `where`, `unique` over a projection, and
a rule `when`:

```cue
{id: "AGG-001", expr: compare: {
    left: {func: {name: "sum", args: [{path: "spec.containers[*].cpu"}]}}
    op: "<="
    right: {literal: 4}
}}
{id: "AGG-004", expr: match: {path: "spec.containers[*].name", unique: true}}
{id: "AGG-005"
    when: match: {path: "metadata.labels.env", equals: "prod"}
    expr: forEach: {
        path: "spec.containers", as: "c"
        condition: match: {path: "c.resources.limits.memory", exists: true}
    }
    message: "production container {{c.name}} has no memory limit"
}
```

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "test-aggregate", "metadata": {"name": "web", "labels": {"env": "prod"}}, "spec": {"declaredPorts": [8080], "containers": [{"name": "app", "cpu": 1, "ports": [{"containerPort": 8080}], "resources": {"limits": {"memory": "512Mi"}}}, {"name": "proxy", "cpu": 0.5, "resources": {"limits": {"memory": "128Mi"}}}]}}' -n advanced-operators -p aggregate-checks

# Should DENY: "web requests more than 4 CPUs in total", "2 containers run privileged; at most 1 may",
# "container app exposes undeclared port 9229; container debug exposes undeclared port 6060",
# "production container debug has no memory limit"
garmr eval -d '{"kind": "test-aggregate", "metadata": {"name": "web", "labels": {"env": "prod"}}, "spec": {"declaredPorts": [8080], "containers": [{"name": "app", "cpu": 3, "securityContext": {"privileged": true}, "ports": [{"containerPort": 8080}, {"containerPort": 9229}], "resources": {"limits": {"memory": "512Mi"}}}, {"name": "debug", "cpu": 2, "securityContext": {"privileged": true}, "ports": [{"containerPort": 6060}]}]}}' -n advanced-operators -p aggregate-checks
```

---

### length

Validates string or array length.

**Policy:** `length-constraints` in
`example-policies/advanced-operators/length.cue` (`action: warn`)

```cue
{id: "LEN-001", expr: match: {path: "spec.containers", length: greaterThanOrEqual: 1}}
{id: "LEN-002", expr: match: {path: "spec.containers", length: lessThanOrEqual: 5}}
{id: "LEN-003", expr: match: {path: "spec.availabilityZones", length: equals: 3}}
{id: "LEN-004", expr: match: {path: "metadata.name", length: greaterThan: 2}}
{id: "LEN-005", expr: match: {path: "metadata.tags", length: greaterThan: 0}}
```

**Operators:** `equals`, `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`

Lists count elements; strings count characters (not bytes). The length is
available to the rule's `message` as `{{.length}}`.

**CLI:**
```bash
# Should ALLOW
garmr eval -d '{"kind": "Pod", "metadata": {"name": "web-api", "tags": ["prod"]}, "spec": {"containers": [{"name": "app"}], "availabilityZones": ["a", "b", "c"]}}' -n advanced-operators -p length-constraints

# Should WARN (two zones, name too short, no tags; the policy only warns)
garmr eval -d '{"kind": "Pod", "metadata": {"name": "ab", "tags": []}, "spec": {"containers": [{"name": "app"}], "availabilityZones": ["a", "b"]}}' -n advanced-operators -p length-constraints
```

---

### semver

Compares semantic versions.

**Policy:** `semver-constraints` in
`example-policies/advanced-operators/semver.cue`

```cue
{id: "SV-001", expr: match: {path: "spec.version", semver: greaterThanOrEqual: "2.0.0"}}
{id: "SV-002", expr: match: {path: "spec.version", semver: lessThan: "4.0.0"}}
{id: "SV-003", expr: match: {path: "spec.dependencies.dbDriver", semver: equals: "1.5.2"}}
```

**Operators:** `equals`, `greaterThan`, `greaterThanOrEqual`, `lessThan`, `lessThanOrEqual`, `constraint`

**Versions.** A leading `v` is accepted, and minor and patch may be omitted
(`1.2` is `1.2.0`). Prereleases order below their release and are compared
by SemVer 2.0.0 precedence; build metadata (`+…`) is ignored. The version is
available to the message as `{{.version}}`.

**Constraints** are comma-separated conditions that must all hold:
- `>=1.0.0`, `>1.0.0`, `<=2.0.0`, `<2.0.0`, `=1.2.3` (a bare version also
  means `=`)
- `^1.2.0` - same major version and at least `1.2.0` (`^0.2.0` accepts
  `0.3.0`: the major-version rule applies to `0` too)
- `~1.2.0` - same major and minor version and at least `1.2.0`
- `>=1.0.0,<2.0.0` - range

**CLI:**
```bash
# Should ALLOW (2.1.5 is in [2.0.0, 4.0.0); driver is exactly 1.5.2)
garmr eval -d '{"kind": "App", "spec": {"version": "2.1.5", "dependencies": {"dbDriver": "1.5.2"}}}' -n advanced-operators -p semver-constraints

# Should DENY (1.9.0 fails SV-001)
garmr eval -d '{"kind": "App", "spec": {"version": "1.9.0", "dependencies": {"dbDriver": "1.5.2"}}}' -n advanced-operators -p semver-constraints
```

An unparseable version in the input is an evaluation error and fails the
rule closed ("Rule SV-001 could not be evaluated: 'spec.version' is not a
valid semver: two") — a malformed version never parses as `0.0.0`. An
unparseable version or constraint in the policy is a load error.

---

### datetime

Validates dates and expiration.

**Policy:** `datetime-constraints` in
`example-policies/advanced-operators/datetime.cue`

```cue
{id: "DT-001", expr: match: {path: "spec.certificate.notAfter", datetime: notExpired: true}}
{id: "DT-002", expr: match: {path: "spec.certificate.notAfter", datetime: expiresAfterDays: 30}}
{id: "DT-003", expr: match: {path: "spec.lastSecurityScan", datetime: withinDays: 7}}
{id: "DT-004", expr: match: {path: "spec.buildTimestamp", datetime: withinHours: 24}}
```

**Operators:**
- `after`, `before`, `afterOrEqual`, `beforeOrEqual` - Compare to a date
- `withinDays`, `withinHours` - Within N days/hours of now, in either direction
- `expiresAfterDays` - At least N days in the future
- `notExpired` - `true`: in the future; `false`: in the past

**Formats** (input values and operands): RFC3339 (with or without
fractional seconds), `2006-01-02T15:04:05` (with or without a trailing
`Z`), `2006-01-02 15:04:05`, `2006-01-02`, `01/02/2006`, `02-Jan-2006`, and
`now`. Values without a zone are UTC. The parsed time is available to the
message as `{{.datetime}}`, normalized to RFC3339.

An unparseable datetime in the input is an evaluation error; an
unparseable operand in the policy is a load error.

**CLI:**
```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Should ALLOW (certificate valid for years; scan and build are fresh)
garmr eval -d '{"kind": "Service", "spec": {"certificate": {"notAfter": "2030-01-01T00:00:00Z"}, "lastSecurityScan": "'"$NOW"'", "buildTimestamp": "'"$NOW"'"}}' -n advanced-operators -p datetime-constraints

# Should DENY (certificate expired: DT-001 and DT-002)
garmr eval -d '{"kind": "Service", "spec": {"certificate": {"notAfter": "2024-01-01T00:00:00Z"}, "lastSecurityScan": "'"$NOW"'", "buildTimestamp": "'"$NOW"'"}}' -n advanced-operators -p datetime-constraints
```

---

### compare (Cross-Field)

Compares two values: input fields, literals, or builtin results.

**Policies:** `compare-cross-field`, `compare-literal`, `compare-with-func`
and `compare-env` in `example-policies/advanced-operators/compare.cue`

```cue
// compare-cross-field
{id: "CMP-101", expr: compare: {
    left: {path: "spec.autoscaling.maxReplicas"}
    op: ">"
    right: {path: "spec.autoscaling.minReplicas"}
}}
{id: "CMP-102", expr: compare: {
    left: {path: "spec.resources.memoryLimit"}
    op: ">="
    right: {path: "spec.resources.memoryRequest"}
}}
// compare-literal
{id: "CMP-104", expr: compare: {
    left: {path: "spec.image.tag"}
    op: "matches"
    right: {literal: "^v?[0-9]+\\.[0-9]+\\.[0-9]+$"}
}}
// compare-with-func
{id: "CMP-105", expr: compare: {
    left: {func: {name: "len", args: [{path: "spec.containers"}]}}
    op: "<="
    right: {literal: 5}
}}
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

Operands of the wrong type for an operator are an evaluation error. That
includes two missing fields: both sides resolve to null, and `>` on two
nulls is an error, not a failure. An unknown operator is rejected when the
policy loads.

**Test Data:**
- Fail: `testdata/advanced-operators/compare-fail.yaml` (minReplicas > maxReplicas, memoryRequest > memoryLimit)

**CLI:**
```bash
# Should ALLOW (maxReplicas > minReplicas, limit >= request)
garmr eval -d '{"kind": "Deployment", "spec": {"autoscaling": {"minReplicas": 2, "maxReplicas": 10}, "resources": {"memoryRequest": 256, "memoryLimit": 512}}}' -n advanced-operators -p compare-cross-field

# Should DENY (CMP-101 and CMP-102 fail)
garmr eval --input testdata/advanced-operators/compare-fail.yaml -n advanced-operators -p compare-cross-field
```

**curl:**
```bash
# Should DENY (maxReplicas 5 is not greater than minReplicas 10)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"input": {"kind": "Deployment", "spec": {"autoscaling": {"minReplicas": 10, "maxReplicas": 5}, "resources": {"memoryRequest": 256, "memoryLimit": 512}}}, "namespace": "advanced-operators", "policies": ["compare-cross-field"]}'
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

**Policy:** `service-selectors` in
`example-policies/advanced-operators/aggregate.cue` (targets `kind:
"test-bundle"`).

**CLI:**
```bash
# Should ALLOW (the web Service selects app=web, which the web Deployment's pods carry)
garmr eval -d '{"kind": "test-bundle", "services": [{"metadata": {"name": "web"}, "spec": {"selector": {"app": "web"}}}], "deployments": [{"metadata": {"name": "web"}, "spec": {"template": {"metadata": {"labels": {"app": "web", "tier": "frontend"}}}}}]}' -n advanced-operators -p service-selectors

# Should DENY: "service web does not select the pods of deployment web"
garmr eval -d '{"kind": "test-bundle", "services": [{"metadata": {"name": "web"}, "spec": {"selector": {"app": "website"}}}], "deployments": [{"metadata": {"name": "web"}, "spec": {"template": {"metadata": {"labels": {"app": "web", "tier": "frontend"}}}}}]}' -n advanced-operators -p service-selectors
```

---

### func (Builtins)

Calls a builtin. Arguments are values, like `compare` operands. Without
`expect`, the result must be truthy (not `false`, `0`, `""`, `[]`, `{}` or
null); with `expect`, it must equal it. `bind` names the result for the
rule's `message` template.

**Policies:** `builtin-cidr`, `builtin-k8s-units` (`action: warn`) and
`builtin-type-check` in `example-policies/builtins/func-calls.cue`

```cue
// builtin-cidr
{id: "FN-001", expr: "func": {
    name: "cidrContains"
    args: [{literal: "10.244.0.0/16"}, {path: "spec.podIP"}]
    expect: true
}}
{id: "FN-002", expr: "func": {name: "ipVersion", args: [{path: "spec.serviceIP"}], expect: 4}}

// builtin-k8s-units
{id: "FN-003", expr: compare: {
    left: {func: {name: "unitsParse", args: [{path: "spec.resources.requests.cpu"}]}}
    op:    ">="
    right: {func: {name: "unitsParse", args: [{literal: "100m"}]}}
}}
```

**CLI:**
```bash
# Should ALLOW (pod IP inside 10.244.0.0/16, IPv4 service IP)
garmr eval -d '{"kind": "Pod", "spec": {"podIP": "10.244.3.17", "serviceIP": "10.96.0.10"}}' -n builtins -p builtin-cidr

# Should DENY (pod IP outside the CIDR, IPv6 service IP)
garmr eval -d '{"kind": "Pod", "spec": {"podIP": "192.168.1.5", "serviceIP": "fd00::10"}}' -n builtins -p builtin-cidr
```

#### Builtin reference

An unknown name is rejected when the policy loads. A builtin called with the
wrong number or types of arguments returns an error, which is an
evaluation error for the rule.

| Builtin | Arguments | Returns |
|---------|-----------|---------|
| `len` | string, list or object | Characters, elements or keys |
| `sum`, `min`, `max`, `avg` | list of numbers | Number. Numeric strings (`"2"`) are converted; any other element (including `null`) is an error. `sum` of an empty list is `0`; `min`, `max`, `avg` of an empty list are errors |
| `lower`, `upper` | string | String |
| `trim` | string, optional cutset | String with whitespace (or the cutset characters) removed from both ends |
| `trimPrefix`, `trimSuffix` | string, string | String |
| `split` | string, separator | List of strings |
| `join` | list, separator | String; elements are formatted with Go's `%v` |
| `matches` | string, RE2 pattern | Boolean; patterns are capped at 512 bytes |
| `format` | Go format string, values… | String (`fmt.Sprintf`) |
| `base64Encode` | string | Standard base64 |
| `base64Decode` | string | String; standard alphabet first, then URL-safe |
| `now` | none | The current UTC time as RFC3339 |
| `duration` | Go duration (`"90s"`, `"1h30m"`) | Seconds as a number |
| `parseTime` | string, optional Go layout (default RFC3339) | Unix seconds |
| `typeOf` | any | `"string"`, `"number"`, `"boolean"`, `"array"`, `"object"` or `"null"` |
| `isType` | any, type name | Boolean (`typeOf(value) == name`) |
| `hasKey` | object, key | Boolean; `false` when the first argument is not an object |
| `keys`, `values` | object | List, in sorted key order |
| `lookup` | object, dot-separated path | The value, or `null` when absent (plain keys only: no quoting or indexes) |
| `cidrContains` | CIDR, IP | Boolean |
| `cidrOverlap` | CIDR, CIDR | Boolean |
| `ipVersion` | IP | `4` or `6` |
| `unitsParse` | Kubernetes quantity | Number: `"500m"` → `0.5`, `"2k"` → `2000`, `"1Gi"` → `1073741824` |
| `flatten` | list | List with nested lists flattened recursively |
| `unique` | list | List without duplicates (strict equality), first occurrence kept |
| `sort` | list | Ascending copy; numbers and strings sort among themselves, mixed kinds are grouped by kind |
| `filter` | list, value | The elements equal to the value |

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

reports `container app exposes undeclared port 9229; container debug
exposes undeclared port 6060`. Identical renderings are reported once.
Elements visited inside a branch that ultimately passed (an `any` or `not`)
are not reported. A placeholder that does not resolve is left as written. A
malformed placeholder is a load error.

Bindings render the value the check used: `{{.datetime}}` is the parsed
time normalized to RFC3339 (not the input as written), `{{.version}}` the
version string, `{{.length}}` and `{{.count}}` numbers.

---

## Load-Time Validation

A policy that fails any of these checks is rejected when it loads (startup
fails, a reload keeps the previous set, `garmr validate` and `/v1/validate`
report it):

- The document does not unify with the schema (unknown fields, wrong types).
- An expression sets no operator, or more than one.
- An operand cannot be compiled: a malformed path, an invalid regular
  expression (or one over 512 bytes), semver, semver constraint or datetime
  literal, an unknown builtin or compare operator, or a malformed message
  placeholder.
- A `forEach` has no `condition`, an `as` that is not an identifier, or
  `count` together with `mode` or `allowEmpty`.
- Two rules in the policy share an `id`.
- An exception `match` selects everything (it would disable the policy), or
  its `expiry` is not an RFC3339 timestamp.
- `evaluation.timeout` is not a positive Go duration (`"250ms"`, `"30s"`).
- Two policy documents declare the same `namespace/name`.
- A policy uses the reserved namespace `__system__`.

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
                priority:    10      // optional; lower is evaluated first
                // optional: the rule applies only when this holds
                when: match: {path: "metadata.labels.env", equals: "prod"}
                // the check: exactly one operator per expression
                expr: match: {path: "spec.replicas", greaterThanOrEqual: 2}
                message:     "{{metadata.name}} needs at least 2 replicas"
                remediation: "Set spec.replicas to 2 or more"
                url:         "https://wiki.example.com/policies/RULE-001"
                category:    "availability"
                tags: ["ha", "production"]
            }
        ]
        enforcement: {
            action: "deny"  // deny, warn, audit
            dryRun: false   // true: report, but lower deny to warn
            exceptions: [{
                name:   "legacy-batch"
                reason: "migrating in Q3"
                match: {names: ["batch-*"]}
                expiry:     "2027-06-30T00:00:00Z"
                approvedBy: ["platform-lead"]
                ticket:     "PLAT-1234"
            }]
        }
        evaluation: {
            order:    "priority"  // priority, severity, definition, priority-then-severity
            failFast: false
            timeout:  "250ms"
            // optional rule filters and cap
            excludeTags: ["experimental"]
            maxRules:    0  // 0 = unlimited
        }
    }
}
```

---

## Field Reference

### Identifiers

| Field | Format |
|-------|--------|
| `metadata.name` | `^[a-z][a-z0-9-]{0,62}$`: lowercase, digits and hyphens, starting with a letter |
| `metadata.namespace` | `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`; defaults to `"default"`. `__system__` is reserved |
| Rule `id` | `^[A-Za-z][A-Za-z0-9_-]{0,63}$`; unique within the policy |
| `forEach` `as` | `^[A-Za-z][A-Za-z0-9_]*$` |

`metadata` also takes `labels` and `annotations` (string maps) and any
other fields you want to carry along.

### Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Identifier, reported as `rule_id` |
| `description` | yes | What the rule checks |
| `severity` | yes | `critical`, `high`, `medium`, `low` or `info` |
| `expr` | yes | The check |
| `when` | no | The rule applies only when this holds ([above](#rule-applicability-when)) |
| `priority` | no | 0–9999; lower is evaluated first under the `priority` orders |
| `message` | no | Violation message template ([Messages](#messages)) |
| `remediation` | no | How to fix a violation; returned with the result |
| `url` | no | Documentation link |
| `category` | no | A grouping such as `security`; used by the category filters below |
| `tags` | no | A list of strings; used by the tag filters below |

### `spec.evaluation`

| Field | Default | Description |
|-------|---------|-------------|
| `order` | `priority` | `priority` (rules without a priority last), `severity` (critical first), `definition`, or `priority-then-severity`. Ties keep definition order |
| `failFast` | `false` | Stop at this policy's first failing rule and evaluate no further policies for the request |
| `timeout` | none | Deadline for the request, as a Go duration; the smallest among the matched policies applies. A policy that runs out of time denies |
| `includeCategories` / `excludeCategories` | none | Evaluate only rules whose `category` is listed / skip rules whose `category` is listed |
| `includeTags` / `excludeTags` | none | Evaluate only rules with at least one listed tag / skip rules with any listed tag |
| `maxRules` | `0` | Evaluate at most this many rules of the policy, in evaluation order (`0` = unlimited) |

The filters are part of the policy, not the request: a filtered-out rule is
not evaluated and does not appear in the results.

### `spec.enforcement`

| Field | Default | Description |
|-------|---------|-------------|
| `action` | — | `deny`, `warn` or `audit` ([Enforcement Actions](#enforcement-actions)) |
| `dryRun` | `false` | Report violations but lower this policy's `deny` to `warn` |
| `exceptions` | none | Inputs the whole policy skips (below) |

An exception skips the **whole policy** for inputs its `match` selector
matches; the selector has the same fields as a target selector and must
narrow something.

| Exception field | Required | Description |
|-----------------|----------|-------------|
| `name` | yes | Identifier |
| `reason` | yes | Why the exception exists |
| `match` | yes | Resource selector: `kind`, `apiGroup`, `names`, `namespaces`, `labels`, `annotations` |
| `expiry` | no | RFC3339 timestamp; after it the exception no longer applies |
| `approvedBy` | no | List of approvers, for the record |
| `ticket` | no | Issue tracker reference, for the record |

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
