---
title: "datetime-policy"
description: "Validates dates and expiration"
sidebar:
  order: 2
---

Validates dates and expiration

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `advanced` |
| **Enforcement** | `deny` |
| **Rules** | 3 |
| **Targets** | `certificate`, `secret`, `deployment` |

## Rules

### DATE-001: Certificate must not be expired

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Certificate has expired |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "expiresAt",
    "datetime": {
      "notExpired": true
    }
  }
}
```

</details>

### DATE-002: Certificate must be valid for at least 30 days

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Certificate expires in less than 30 days |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "expiresAt",
    "datetime": {
      "expiresAfterDays": 30
    }
  }
}
```

</details>

### DATE-003: Deployment must be created after 2024

| Property | Value |
|----------|-------|
| **Severity** | `low` |
| **Message** | Deployment predates 2024 |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "metadata.createdAt",
    "datetime": {
      "after": "2024-01-01"
    }
  }
}
```

</details>
