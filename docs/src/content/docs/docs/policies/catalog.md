---
title: "Example Policy Catalog"
description: "Every policy shipped in example-policies/, grouped by namespace"
sidebar:
  order: 2
  label: "Example Policy Catalog"
---

Garmr ships these example policies under `example-policies/`. The test suite
compiles all of them on every CI run, so everything listed here loads against
the current schema.

Try any of them:

```bash
garmr-server --dev --policy-dir ./example-policies
garmr eval -i testdata/real-world/k8s-pod-security-context-fail.yml -n security
```

To render full reference pages — for these or for your own policies:

```bash
garmr docs generate ./example-policies --out-dir ./out/docs
```

:::note
This page is maintained by hand. Generated pages used to be committed under
`docs/policies/generated/`, but nothing regenerated or verified them and they
drifted: most described policies that no longer existed, while whole example
families had no page at all. `garmr docs generate` runs offline against any
policy tree — point it at yours.
:::


## `advanced-operators`

`forEach` (including `where` filters and counting), rule `when`, `length`, `semver`, `datetime`, cross-field `compare`, `[*]` projections, and messages that name the failing element.

Source: `example-policies/advanced-operators/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `aggregate-checks` | 5 | Checks across all containers: total CPU via a `[*]` projection, a counted `forEach`, undeclared ports (`where`) with per-container messages, unique names, and a production-only rule (`when`) |
| `compare-cross-field` | 2 | Compares two fields from the input against each other |
| `compare-env` | 1 | Compares a deployment target against the cluster it was approved for |
| `compare-literal` | 2 | Compares input fields against literal values using various operators |
| `compare-with-func` | 1 | Uses builtin functions within compare expressions |
| `datetime-constraints` | 4 | Validates datetime fields for expiry, freshness, and time-window compliance |
| `foreach-all` | 2 | Iterates over containers — every container must pass all checks |
| `foreach-any` | 1 | Iterates over a collection — at least one element must match |
| `foreach-nested` | 1 | Complex per-element checks combining forEach with logical operators |
| `length-constraints` | 5 | Validates array and string lengths using various length operators |
| `semver-constraints` | 3 | Validates semantic versioning constraints on application versions |
| `service-selectors` | 1 | Joins Services to Deployments by name (`where`) and checks each selector with `compare` `subsetOf` |


## `builtins`

Built-in function calls: strings, encoding, CIDR, Kubernetes units, type checks.

Source: `example-policies/builtins/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `builtin-cidr` | 2 | Uses cidrContains and ipVersion builtins for network validation |
| `builtin-encoding` | 2 | Uses encoding and string builtins for data validation |
| `builtin-k8s-units` | 1 | Uses unitsParse to validate Kubernetes resource quantities |
| `builtin-map-ops` | 1 | Uses map-related builtins for structured data validation |
| `builtin-type-check` | 2 | Uses typeOf and isType builtins to validate field types |


## `cloud-governance`

Cloud resource governance, including a Terraform-plan variant.

Source: `example-policies/real-world/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `cloud-resource-governance-terraform` | 6 | Enforces governance standards on Terraform plan JSON (terraform show -json) |
| `cloud-resource-governance` | 6 | Enforces resource governance standards for cost control and operational excellence |


## `collections`

List membership with `match.containsAll` and `match.containsAny`.

Source: `example-policies/collections/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `contains-all` | 2 | Checks that a collection contains ALL of the required values |
| `contains-any` | 2 | Checks that a collection contains at least one of the specified values |
| `contains-value` | 2 | Checks if a collection contains a specific value |


## `condition-operators`

The core `match` operators, plus `all` / `any` / `not`.

Source: `example-policies/condition-operators/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `absent-operator` | 2 | Validates field absence using match.exists: false |
| `equals-boolean` | 1 | Validates boolean field matching using the equals operator |
| `equals-numeric` | 1 | Validates exact numeric matching using the equals operator |
| `equals-string` | 2 | Validates exact string matching using the equals operator |
| `exists-operator` | 2 | Validates field existence using match.exists |
| `logical-all` | 1 | Demonstrates the 'all' (AND) combinator — every condition must pass |
| `logical-any` | 1 | Demonstrates the 'any' (OR) combinator — at least one condition must pass |
| `logical-nested` | 1 | Demonstrates nested logical operators: all containing any and not |
| `logical-not` | 1 | Demonstrates the 'not' combinator — the inner expression must fail |
| `numeric-comparison` | 4 | Validates numeric fields using comparison operators |
| `set-advanced` | 5 | Validates arrays with unique, uniqueBy, sorted, containsAll, and subsetOf |
| `set-membership` | 3 | Validates set membership using in and notIn operators |
| `string-matching` | 4 | Validates string fields using substring and regex operators |


## `enforcement`

Enforcement actions: deny, warn, audit, dry-run, fail-fast, exceptions.

Source: `example-policies/enforcement/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `enforce-audit` | 1 | Audit enforcement — violations are recorded for reporting only |
| `enforce-deny` | 1 | Deny enforcement — violations produce a 'deny' decision |
| `enforce-dry-run` | 1 | Dry-run mode — deny is downgraded to warn with [DRY RUN] prefix |
| `enforce-fail-fast` | 3 | Fail-fast evaluation — stops at the first rule failure |
| `enforce-warn` | 2 | Warn enforcement — violations produce a 'warn' decision instead of 'deny' |
| `enforce-with-exceptions` | 1 | Deny policy with exceptions for specific resources |


## `release`

Release-gate policies, including the `garmr test` worked example.

Source: `example-policies/real-world/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `release-advisory` | 3 | Warns on non-critical release-quality issues; reports all advisory failures |
| `release-gate` | 4 | Denies promotion on any critical release violation; reports all critical failures |


## `security`

Container security baselines and certificate management.

Source: `example-policies/real-world/`

| Policy | Rules | Description |
|--------|-------|-------------|
| `certificate-management` | 6 | Validates TLS certificate configuration, expiry, and compliance |
| `container-security` | 6 | Enforces container security best practices for Kubernetes workloads |


---

43 policies across 8 namespaces.
