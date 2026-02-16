---
title: "Advanced Policies"
description: "Advanced namespace policies for Garmr"
sidebar:
  order: 0
---

This namespace contains 5 policies.

## Policies

| Policy | Description | Rules | Enforcement |
|--------|-------------|-------|-------------|
| [cross-field-policy](/garmr/docs/policies/generated/advanced/cross-field-policy/) | Validates relationships between fields | 2 | `deny` |
| [datetime-policy](/garmr/docs/policies/generated/advanced/datetime-policy/) | Validates dates and expiration | 3 | `deny` |
| [k8s-container-policy](/garmr/docs/policies/generated/advanced/k8s-container-policy/) | Kubernetes container security - validates all containers in a pod | 3 | `deny` |
| [length-policy](/garmr/docs/policies/generated/advanced/length-policy/) | Validates lengths of arrays and strings | 3 | `warn` |
| [semver-policy](/garmr/docs/policies/generated/advanced/semver-policy/) | Validates semantic versions | 3 | `deny` |
