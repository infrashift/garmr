---
title: "numeric-test"
description: "Numeric comparison test policy"
sidebar:
  order: 2
---

Numeric comparison test policy

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `test` |
| **Enforcement** | `deny` |
| **Rules** | 2 |
| **Targets** | `test` |

## Rules

### NUM-001: Count must be positive

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Count must be greater than 0 |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "count",
    "greaterThan": 0
  }
}
```

</details>

### NUM-002: Score must be at least 50

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Score is below 50 |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "score",
    "greaterThanOrEqual": 50
  }
}
```

</details>
