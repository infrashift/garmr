---
title: "Target & Namespace Filtering"
description: "How to scope policies to specific resources and namespaces"
sidebar:
  order: 2
  label: "Filtering"
---

This guide explains how Garmr determines which policies apply to which resources.

## Overview

Garmr uses two complementary filtering mechanisms:

1. **Target Filtering** - Which resource types a policy applies to (defined in policy)
2. **Namespace Filtering** - Which policy namespaces to evaluate (specified at runtime)

These work together with AND logic:

```
Applicable Policies = (matches target) AND (matches namespace filter)
```

---

## Target Filtering

Target filtering is defined **in the policy** and controls which resource types the policy applies to.

### Basic Target

Match resources by kind:

```cue
spec: {
    target: {
        resources: ["pod", "deployment", "statefulset"]
    }
}
```

This policy applies to any input where `kind` (case-insensitive) matches one of the listed resources.

### Wildcard Target

Match all resources:

```cue
spec: {
    target: {
        resources: ["*"]
    }
}
```

### Structured Target

For fine-grained control, use structured resource selectors:

```cue
spec: {
    target: {
        resources: [
            {
                kind: "deployment"
                apiGroup: "apps"   // the group of apiVersion "apps/v1"
                namespaces: ["production", "staging"]
                labels: {
                    "app.kubernetes.io/managed-by": "helm"
                }
            },
            {
                kind: "pod"
                namespaces: ["production"]
                annotations: {
                    "garmr.io/enforce": "true"
                }
            }
        ]
    }
}
```

### Target Selector Fields

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Resource kind (supports wildcards) |
| `apiGroup` | string | API group, matched against the group part of the input's `apiVersion` (`"apps"` for `apps/v1`; `""` is the core group of `v1`). Defaults to `"*"`, any group. Supports wildcards |
| `names` | []string | Resource name (`metadata.name`) must match one entry (supports wildcards) |
| `namespaces` | []string | Resource namespace (`metadata.namespace`) must match one entry (supports wildcards) |
| `labels` | map | All specified labels must be present on `metadata.labels`; values support wildcards |
| `annotations` | map | All specified annotations must be present on `metadata.annotations`; values support wildcards |

All selector fields are enforced during evaluation. There are no `excludeNames`/`excludeNamespaces` fields.

### Wildcard Matching

Selector values support glob-style `*` wildcards (matching is case-insensitive):

```cue
target: {
    resources: [
        {
            kind: "deployment"
            names: ["prod-*", "*-api"]        // Matches prod-web, user-api
            namespaces: ["prod-*"]            // Matches prod-us, prod-eu
            annotations: {"team": "platform-*"}
        }
    ]
}
```

### No Target (Default)

If no target is specified (or `resources` is empty), the policy applies to
**all resources**:

```cue
spec: {
    // No target block = matches everything
    rules: [...]
}
```

---

## Namespace Filtering

Namespace filtering is specified **at evaluation time** and controls which policy namespaces are evaluated.

### Policy Namespaces vs Resource Namespaces

These are different concepts:

| Concept | Definition | Example |
|---------|------------|---------|
| **Policy Namespace** | Organizational grouping of policies | `security`, `release`, `compliance` |
| **Resource Namespace** | Kubernetes namespace in the input | `production`, `default` |

Policy namespace is defined in the policy metadata:

```cue
metadata: {
    name: "container-security"
    namespace: "security"  // Policy namespace
}
```

Resource namespace comes from the input:

```json
{
    "kind": "Pod",
    "metadata": {
        "namespace": "production"
    }
}
```

### CLI Namespace Filter

```bash
# Evaluate against all policies (no filter)
garmr eval --input pod.json

# Evaluate only security policies
garmr eval --input pod.json -n security
```

The `-n`/`--namespace` flag takes a single namespace per invocation. To cover multiple namespaces, run `garmr eval` once per namespace (or omit the flag to evaluate all).

### API Namespace Filter

```bash
# No namespace filter
curl -X POST http://localhost:8080/v1/evaluate \
  -d '{"input": {...}}'

# Filter to security namespace
curl -X POST http://localhost:8080/v1/evaluate \
  -d '{"input": {...}, "namespace": "security"}'
```

### Selecting Specific Policies

To evaluate named policies only, list them with `-p`/`--policy`
(repeatable or comma-separated) or `"policies"` in the request body. Each
entry is either `namespace/name` or a bare `metadata.name`, which is looked
up in the namespace given with `-n` / `"namespace"` (`default` when
omitted). A qualified name ignores the namespace filter, so one request can
name policies from several namespaces. A named policy still runs only if its
target matches the input:

```bash
garmr eval --input pod.json -p security/container-security,release/release-gate
garmr eval --input pod.json -n security -p container-security,network-policy

curl -X POST http://localhost:8080/v1/evaluate \
  -d '{"input": {...}, "policies": ["security/container-security"]}'
```

If a named policy does not exist, or none of the named policies targets the
input, the request is denied (under the default `require_match`) with a
result explaining which.

---

## How Filtering Works Together

### Evaluation Flow

```
Input Resource
     │
     ▼
┌─────────────────────┐
│ Namespace Filter    │ ← Runtime filter (-n flag)
│ (policy namespace)  │
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│ Target Filter       │ ← Policy-defined filter
│ (resource matching) │
└─────────────────────┘
     │
     ▼
Applicable Policies
```

### Example Scenario

**Policies loaded:**

| Policy | Namespace | Target |
|--------|-----------|--------|
| container-security | security | pod, deployment |
| network-policy | security | pod, service |
| release-gate | release | release |
| audit-logging | compliance | * |

**Input:** `{"kind": "Pod", "metadata": {"name": "web"}}`

| Command | Policies Evaluated |
|---------|-------------------|
| `garmr eval --input pod.json` | container-security, network-policy, audit-logging |
| `garmr eval --input pod.json -n security` | container-security, network-policy |
| `garmr eval --input pod.json -n release` | (none - release policies don't target pods) |
| `garmr eval --input pod.json -n compliance` | audit-logging |

---

## Filtering Strategies

### Strategy 1: Team-Based Namespaces

Organize policies by owning team:

```
policies/
├── platform/           # Platform team policies
│   ├── resource-limits.cue
│   └── naming-conventions.cue
├── security/           # Security team policies
│   ├── container-hardening.cue
│   └── network-policy.cue
└── compliance/         # Compliance team policies
    ├── pci-dss.cue
    └── hipaa.cue
```

Usage:
```bash
# Security review
garmr eval --input deployment.json -n security

# Full compliance check (one namespace per invocation)
garmr eval --input deployment.json -n security
garmr eval --input deployment.json -n compliance
```

### Strategy 2: Environment-Based Namespaces

Organize by deployment environment:

```
policies/
├── dev/                # Development policies (lenient)
├── staging/            # Staging policies (moderate)
└── prod/               # Production policies (strict)
```

Usage:
```bash
# CI for dev branch
garmr eval --input deployment.json -n dev

# CI for production deploy
garmr eval --input deployment.json -n prod
```

### Strategy 3: Pipeline Stage Gates

Organize by release pipeline stage:

```
policies/
├── build/              # Build-time checks
├── test/               # Test environment gates
├── staging/            # Pre-production gates
└── release/            # Production release gates
```

Usage:
```bash
# After build
garmr eval --input artifact.json -n build

# Before production
garmr eval --input artifact.json -n release
```

### Strategy 4: Resource-Type Targeting

Use target filtering for resource-specific policies (excerpts: `apiVersion`,
`kind`, rules and `enforcement` omitted):

```cue
// policies/k8s/workloads.cue
package k8s

workloadSecurity: {
    metadata: {
        name: "workload-security"
        namespace: "k8s"
    }
    spec: {
        target: resources: ["deployment", "statefulset", "daemonset"]
        rules: [...]
    }
}

// policies/k8s/networking.cue
networkSecurity: {
    metadata: {
        name: "network-security"
        namespace: "k8s"
    }
    spec: {
        target: resources: ["service", "ingress", "networkpolicy"]
        rules: [...]
    }
}
```

The correct policies are automatically selected based on input kind.

---

## Best Practices

### 1. Use Namespaces for Organizational Boundaries

```
Good: security/, compliance/, platform/
Bad:  policy1/, policy2/, misc/
```

### 2. Use Targets for Resource Scoping

```cue
// Good: Explicit targeting
target: resources: ["deployment", "statefulset"]

// Avoid: Overly broad
target: resources: ["*"]  // Only when truly universal
```

### 3. Combine Both for Precision

```cue
// Security policies that only apply to production workloads
metadata: namespace: "security"
spec: {
    target: {
        resources: [{
            kind: "deployment"
            namespaces: ["production"]
        }]
    }
}
```

### 4. Document Your Strategy

Create a README in your policies directory:

```markdown
# Policy Organization

## Namespaces
- `security/` - Security team policies, reviewed quarterly
- `compliance/` - Regulatory requirements (PCI, HIPAA)
- `platform/` - Platform standards, owned by SRE

## CI/CD Usage
- PR checks: run eval with `-n security`, then `-n platform`
- Production deploy: run eval for each of `security`, `compliance`, `platform`
```

---

## Debugging Filtering Issues

### Policy Not Being Evaluated?

```bash
# Check what policies are loaded
garmr policy list

# Check what namespace a policy is in
garmr policy list -o json | jq '.policies[] | {name, namespace}'

# Evaluate without namespace filter to see all matches
garmr eval --input resource.json -o json | jq '.results[].policy_namespace'
```

### Target Not Matching?

```bash
# Check the input kind
cat resource.json | jq '.kind'

# Check policy targets
grep -A5 "target:" policies/*.cue
```

### See All Evaluated Policies

```bash
# Include passed rules to see full evaluation
garmr eval --input resource.json --verbose -o json | \
  jq '[.results[] | {policy: .policy_name, namespace: .policy_namespace}] | unique'
```
