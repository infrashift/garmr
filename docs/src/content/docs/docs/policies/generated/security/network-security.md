---
title: "network-security"
description: "Network security requirements"
sidebar:
  order: 1
---

Network security requirements

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `security` |
| **Enforcement** | `warn` |
| **Rules** | 2 |
| **Targets** | `service`, `ingress`, `networkpolicy` |

### Labels

| Key | Value |
|-----|-------|
| `category` | `security` |
| `framework` | `network` |

## Rules

### NET-001: External services must use HTTPS

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | External service is not using HTTPS |

<details>
<summary>Expression</summary>

```json
{
  "any": [
    {
      "match": {
        "path": "spec.tls.enabled",
        "equals": true
      }
    },
    {
      "match": {
        "path": "spec.protocol",
        "equals": "HTTPS"
      }
    },
    {
      "match": {
        "path": "spec.internal",
        "equals": true
      }
    }
  ]
}
```

</details>

### NET-002: Service ports must be in allowed range

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Service port is not in allowed range (1024-65535) |

<details>
<summary>Expression</summary>

```json
{
  "all": [
    {
      "match": {
        "path": "spec.port",
        "greaterThanOrEqual": 1024
      }
    },
    {
      "match": {
        "path": "spec.port",
        "lessThanOrEqual": 65535
      }
    }
  ]
}
```

</details>
