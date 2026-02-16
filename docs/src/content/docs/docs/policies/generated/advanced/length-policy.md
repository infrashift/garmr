---
title: "length-policy"
description: "Validates lengths of arrays and strings"
sidebar:
  order: 3
---

Validates lengths of arrays and strings

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `advanced` |
| **Enforcement** | `warn` |
| **Rules** | 3 |
| **Targets** | `deployment` |

## Rules

### LEN-001: Name must be between 3 and 63 characters

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Name must be between 3 and 63 characters |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "metadata.name",
    "length": {
      "min": 3,
      "max": 63
    }
  }
}
```

</details>

### LEN-002: Must have at least 2 replicas

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | At least 2 replicas required for high availability |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "spec.replicas",
    "greaterThanOrEqual": 2
  }
}
```

</details>

### LEN-003: Labels must not be empty

| Property | Value |
|----------|-------|
| **Severity** | `low` |
| **Message** | At least one label is required |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "metadata.labels",
    "length": {
      "greaterThan": 0
    }
  }
}
```

</details>
