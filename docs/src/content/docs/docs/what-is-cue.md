---
title: "What is CUE?"
description: "An introduction to the CUE language and why Garmr uses it for policy definitions"
sidebar:
  order: 2
  label: "What is CUE?"
---

CUE is an open-source language for defining, generating, and validating configuration. It combines the best ideas from logic programming, functional programming, and schema languages into a single, compact syntax.

Garmr uses CUE as its policy language because CUE treats types and values as the same thing -- constraints. This means your policies are validated at authoring time, not just at evaluation time.

## CUE in 60 Seconds

CUE looks like JSON but with types, constraints, and logic built in:

```go
// A simple CUE definition
name: string & =~"^[a-z]"   // Must be a string starting with lowercase
port: int & >0 & <=65535     // Must be an integer in valid port range
env:  "dev" | "staging" | "prod"  // Must be one of these values
```

Unlike YAML or JSON, CUE catches errors before anything runs:

```go
// This is valid
name: "myapp"
port: 8080
env:  "prod"

// This fails immediately -- CUE won't let you proceed
name: "Myapp"    // Error: does not match ^[a-z]
port: 70000      // Error: > 65535
env:  "testing"  // Error: not one of "dev", "staging", "prod"
```

## The Power of Turing Incompleteness

Most configuration and policy languages fall into one of two camps: too simple (YAML, JSON) or too powerful (general-purpose scripting). CUE occupies a deliberate middle ground.

CUE is **intentionally not Turing-complete**. There are no loops, no mutable variables, no unbounded recursion, and no side effects. This might sound like a limitation, but it is CUE's greatest strength:

- **Guaranteed termination** -- every CUE evaluation finishes. There is no possibility of infinite loops, runaway recursion, or resource exhaustion. When you load a policy, you know it will complete.
- **Total analyzability** -- because CUE programs always terminate, tooling can fully reason about what a configuration does. Linters, formatters, and validators can make strong guarantees that are impossible in Turing-complete languages.
- **Safe composition** -- CUE values form a lattice where any two configurations can be merged without ambiguity. Order doesn't matter. There are no override surprises. If two constraints conflict, CUE reports an error rather than silently picking a winner.
- **Hermetic evaluation** -- the same CUE input always produces the same output, regardless of environment, execution order, or platform. Policies behave identically in CI, staging, and production.

This matters enormously for policy. OPA's Rego is Turing-complete, which means a policy *could* loop forever or produce different results depending on evaluation order. With CUE, that class of bugs simply cannot exist.

## Why Garmr Chose CUE

We evaluated several languages for Garmr's policy engine -- Rego (OPA), CEL, Jsonnet, HCL, and CUE. We chose CUE because it uniquely solves problems that plague policy-as-code in practice:

**Policies that validate themselves.** In Rego, you write a policy and hope the structure is correct. In CUE, the policy schema is expressed as constraints in the same language as the policy itself. If you misspell a severity level or use an invalid operator, CUE rejects the policy at load time -- before it ever evaluates input.

**No "policy for your policy" problem.** With Turing-complete policy languages, you often need meta-policies to guard against dangerous constructs (infinite loops, excessive resource use, nondeterminism). CUE eliminates this category entirely. Every policy is safe by construction.

**Configuration and policy in one language.** Many teams already use (or should use) CUE for Kubernetes manifests, Terraform configurations, CI/CD pipelines, and API schemas. Using CUE for policy means your team learns one language for both configuration and governance. Shared CUE definitions, such as a list of allowed registries or approved regions, can feed directly into your policy definitions.

**Review-friendly diffs.** CUE's declarative nature means policy changes produce clean, readable diffs in pull requests. There is no imperative logic to trace, no function call chains to follow -- just constraints that tighten or loosen.

## CUE's Core Ideas

### Types Are Constraints

In most policy languages, you write rules that check data after the fact. In CUE, the schema *is* the rule. If a policy field expects a severity of `"low" | "medium" | "high" | "critical"`, CUE rejects anything else the moment you write it -- no evaluation needed.

### Schema and Data Unification

CUE unifies schemas and values into a single lattice. You can start with loose constraints and progressively tighten them:

```go
// Base definition
deployment: {
    replicas: int & >0
    image:    string
}

// Tighten for production
deployment: {
    replicas: >=3          // At least 3 in prod
    image:    =~"^gcr.io/" // Must come from our registry
}

// CUE merges these automatically -- both constraints apply
```

### Package System

CUE has a real package system with imports, definitions, and visibility controls. Policies can share common definitions, import standard libraries, and compose cleanly across teams.

## How Garmr Uses CUE

Garmr policies are CUE files that follow a defined schema. The CUE language handles:

- **Policy structure validation** -- ensures every policy has the required fields (name, rules, severity, etc.)
- **Constraint checking** -- validates that operator names, severity levels, and enforcement modes are valid values
- **Type safety** -- catches misconfigurations in policy definitions at load time, before any evaluation occurs
- **Composition** -- policies can import shared definitions and build on common patterns

A Garmr policy looks like this:

```go
package policies

containerSecurity: {
    apiVersion: "policy.garmr.io/v1"
    kind:       "Policy"
    metadata: {
        name:      "container-security"
        namespace: "security"
    }
    spec: {
        description: "Enforce container image policies"
        target: resources: ["Deployment", "Pod"]

        rules: [{
            id:          "SEC-001"
            description: "No privileged containers"
            severity:    "critical"
            message:     "Containers must not run in privileged mode"
            expr: match: {
                path:   "spec.privileged"
                equals: false
            }
        }]
        enforcement: action: "deny"
    }
}
```

This is plain CUE. The Garmr schema validates the structure when the policy loads. Each rule's `expr` uses Garmr's operators (`match`, `compare`, `forEach`, `func`, combined with `all`/`any`/`not`), not raw CUE constraints on the input. CUE is used only at load time: the loader compiles each rule into a Go evaluation tree, and the engine evaluates that tree against input data at runtime without running CUE.

## CUE Beyond Policy

CUE is useful far beyond policy engines. Once your team learns CUE for Garmr policies, you can apply it across your infrastructure stack:

- **Kubernetes manifests** -- validate and generate deployment configs with type-safe constraints
- **CI/CD pipelines** -- define pipeline configurations that catch errors before they run (Dagger uses CUE natively)
- **API schemas** -- generate OpenAPI specs and validate API contracts
- **Infrastructure as Code** -- layer environment-specific constraints onto base configurations
- **Data validation** -- validate JSON, YAML, and TOML files against CUE schemas

Learn more at [cuelang.org](https://cuelang.org/):

- [Tutorials](https://cuelang.org/docs/tutorials/) -- hands-on guides to get started
- [Playground](https://cuelang.org/play/) -- try CUE in your browser
- [Language Specification](https://cuelang.org/docs/reference/spec/) -- the complete reference
- [Integrations](https://cuelang.org/docs/integrations/) -- CUE with Go, Kubernetes, and more
