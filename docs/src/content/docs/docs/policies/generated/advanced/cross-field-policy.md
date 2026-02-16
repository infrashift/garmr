---
title: "cross-field-policy"
description: "Validates relationships between fields"
sidebar:
  order: 1
---

Validates relationships between fields

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `advanced` |
| **Enforcement** | `deny` |
| **Rules** | 2 |
| **Targets** | `autoscaler`, `deployment` |

## Rules

### CROSS-001: minReplicas must be <= maxReplicas

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | minReplicas cannot be greater than maxReplicas |

<details>
<summary>Expression</summary>

```json
{
  "compare": {
    "left": {
      "path": "spec.minReplicas"
    },
    "op": "<=",
    "right": {
      "path": "spec.maxReplicas"
    }
  }
}
```

</details>

### CROSS-002: Memory request must be <= memory limit

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Memory request exceeds memory limit |

<details>
<summary>Expression</summary>

```json
{
  "compare": {
    "left": {
      "path": "spec.resources.requests.memory"
    },
    "op": "<=",
    "right": {
      "path": "spec.resources.limits.memory"
    }
  }
}
```

</details>
