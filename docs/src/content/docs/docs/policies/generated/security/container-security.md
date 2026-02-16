---
title: "container-security"
description: "Container security requirements based on CIS benchmarks"
sidebar:
  order: 2
---

Container security requirements based on CIS benchmarks

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `security` |
| **Enforcement** | `deny` |
| **Rules** | 6 |
| **Targets** | `container`, `pod`, `deployment` |

### Labels

| Key | Value |
|-----|-------|
| `category` | `security` |
| `framework` | `cis-benchmark` |

## Rules

### SEC-001: Containers must not run as privileged

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Container is running in privileged mode |

<details>
<summary>Expression</summary>

```json
{
  "any": [
    {
      "match": {
        "path": "spec.privileged",
        "exists": false
      }
    },
    {
      "match": {
        "path": "spec.privileged",
        "equals": false
      }
    }
  ]
}
```

</details>

### SEC-002: Containers must not run as root

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Container may be running as root |

<details>
<summary>Expression</summary>

```json
{
  "any": [
    {
      "match": {
        "path": "spec.runAsNonRoot",
        "equals": true
      }
    },
    {
      "match": {
        "path": "spec.runAsUser",
        "greaterThan": 0
      }
    }
  ]
}
```

</details>

### SEC-003: Root filesystem should be read-only

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Root filesystem is not read-only |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "spec.readOnlyRootFilesystem",
    "equals": true
  }
}
```

</details>

### SEC-004: Resource limits must be defined

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Resource limits are not defined |

<details>
<summary>Expression</summary>

```json
{
  "all": [
    {
      "match": {
        "path": "spec.resources.limits.memory",
        "exists": true
      }
    },
    {
      "match": {
        "path": "spec.resources.limits.cpu",
        "exists": true
      }
    }
  ]
}
```

</details>

### SEC-005: Container image must be from allowed registry

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Container image is not from an allowed registry |

<details>
<summary>Expression</summary>

```json
{
  "any": [
    {
      "match": {
        "path": "spec.image",
        "hasPrefix": "gcr.io/"
      }
    },
    {
      "match": {
        "path": "spec.image",
        "hasPrefix": "docker.io/library/"
      }
    },
    {
      "match": {
        "path": "spec.image",
        "hasPrefix": "ghcr.io/"
      }
    }
  ]
}
```

</details>

### SEC-006: Container image must not use 'latest' tag

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | Container image uses 'latest' tag |

<details>
<summary>Expression</summary>

```json
{
  "not": {
    "match": {
      "path": "spec.image",
      "hasSuffix": ":latest"
    }
  }
}
```

</details>
