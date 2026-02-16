---
title: "acceptance-gate"
description: "Acceptance environment gate"
sidebar:
  order: 1
---

Acceptance environment gate

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `release` |
| **Enforcement** | `deny` |
| **Rules** | 4 |
| **Targets** | `deployment`, `release` |

### Labels

| Key | Value |
|-----|-------|
| `environment` | `acceptance` |

## Rules

### ACC-001: All tests must pass

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

### ACC-002: Integration tests must pass

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Integration tests have not passed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "tests.integration.passed",
    "equals": true
  }
}
```

</details>

### ACC-003: Code coverage minimum 75%

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Code coverage below 75% |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "coverage",
    "greaterThanOrEqual": 75
  }
}
```

</details>

### ACC-004: No critical security issues

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
