---
title: "dev-gate"
description: "Development environment gate - minimal checks"
sidebar:
  order: 2
---

Development environment gate - minimal checks

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `release` |
| **Enforcement** | `warn` |
| **Rules** | 1 |
| **Targets** | `deployment`, `release` |

### Labels

| Key | Value |
|-----|-------|
| `environment` | `dev` |

## Rules

### DEV-001: Build must complete

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Build has not completed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "build.completed",
    "equals": true
  }
}
```

</details>
