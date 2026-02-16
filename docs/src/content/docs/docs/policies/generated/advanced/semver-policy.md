---
title: "semver-policy"
description: "Validates semantic versions"
sidebar:
  order: 4
---

Validates semantic versions

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `advanced` |
| **Enforcement** | `deny` |
| **Rules** | 3 |
| **Targets** | `release`, `deployment` |

## Rules

### SEM-001: Application version must be at least 1.0.0

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Application version must be >= 1.0.0 for production |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "version",
    "semver": {
      "greaterThanOrEqual": "1.0.0"
    }
  }
}
```

</details>

### SEM-002: API version must be v2.x

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | API version must be 2.x compatible |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "apiVersion",
    "semver": {
      "constraint": "^2.0.0"
    }
  }
}
```

</details>

### SEM-003: No alpha or beta releases in production

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Pre-release versions not allowed in production |

<details>
<summary>Expression</summary>

```json
{
  "not": {
    "any": [
      {
        "match": {
          "path": "version",
          "contains": "-alpha"
        }
      },
      {
        "match": {
          "path": "version",
          "contains": "-beta"
        }
      },
      {
        "match": {
          "path": "version",
          "contains": "-rc"
        }
      }
    ]
  }
}
```

</details>
