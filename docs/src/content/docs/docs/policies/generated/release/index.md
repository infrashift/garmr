---
title: "Release Policies"
description: "Release namespace policies for Garmr"
sidebar:
  order: 0
---

This namespace contains 5 policies.

## Policies

| Policy | Description | Rules | Enforcement |
|--------|-------------|-------|-------------|
| [acceptance-gate](/garmr/docs/policies/generated/release/acceptance-gate/) | Acceptance environment gate | 4 | `deny` |
| [dev-gate](/garmr/docs/policies/generated/release/dev-gate/) | Development environment gate - minimal checks | 1 | `warn` |
| [prod-gate](/garmr/docs/policies/generated/release/prod-gate/) | Production environment gate - strictest requirements | 6 | `deny` |
| [release-gate](/garmr/docs/policies/generated/release/release-gate/) | Production release gate requirements | 5 | `deny` |
| [test-gate](/garmr/docs/policies/generated/release/test-gate/) | Test environment gate | 2 | `deny` |
