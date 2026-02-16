---
title: "test-gate"
description: "Test environment gate"
sidebar:
  order: 5
---

Test environment gate

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `release` |
| **Enforcement** | `deny` |
| **Rules** | 2 |
| **Targets** | `deployment`, `release` |

### Labels

| Key | Value |
|-----|-------|
| `environment` | `test` |

## Rules

### TST-001: Unit tests must pass

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Unit tests have not passed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "tests.unit.passed",
    "equals": true
  }
}
```

</details>

### TST-002: Code coverage minimum 60%

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Code coverage below 60% |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "coverage",
    "greaterThanOrEqual": 60
  }
}
```

</details>
