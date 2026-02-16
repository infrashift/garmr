---
title: "release-gate"
description: "Production release gate requirements"
sidebar:
  order: 4
---

Production release gate requirements

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `release` |
| **Enforcement** | `deny` |
| **Rules** | 5 |
| **Targets** | `deployment`, `release` |

## Rules

### REL-001: All tests must pass

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Tests have not passed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "tests.passed",
    "equals": true
  }
}
```

</details>

### REL-002: No test failures allowed

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | There are test failures |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "tests.failures",
    "equals": 0
  }
}
```

</details>

### REL-003: Code coverage must be at least 80%

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Code coverage is below 80% |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "coverage",
    "greaterThanOrEqual": 80
  }
}
```

</details>

### REL-004: No critical security findings

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Critical security findings detected |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "security.criticalFindings",
    "equals": 0
  }
}
```

</details>

### REL-005: Artifact must be signed

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Artifact is not signed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "artifact.signed",
    "equals": true
  }
}
```

</details>
