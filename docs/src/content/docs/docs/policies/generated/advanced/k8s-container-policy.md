---
title: "k8s-container-policy"
description: "Kubernetes container security - validates all containers in a pod"
sidebar:
  order: 5
---

Kubernetes container security - validates all containers in a pod

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `advanced` |
| **Enforcement** | `deny` |
| **Rules** | 3 |
| **Targets** | `pod`, `deployment` |

## Rules

### K8S-001: All containers must have resource limits

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | One or more containers missing resource limits |

<details>
<summary>Expression</summary>

```json
{
  "forEach": {
    "path": "spec.containers",
    "as": "container",
    "condition": {
      "all": [
        {
          "match": {
            "path": "container.resources.limits.memory",
            "exists": true
          }
        },
        {
          "match": {
            "path": "container.resources.limits.cpu",
            "exists": true
          }
        }
      ]
    }
  }
}
```

</details>

### K8S-002: All containers must use allowed registries

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | One or more containers use unauthorized image registries |

<details>
<summary>Expression</summary>

```json
{
  "forEach": {
    "path": "spec.containers",
    "as": "container",
    "condition": {
      "any": [
        {
          "match": {
            "path": "container.image",
            "hasPrefix": "gcr.io/"
          }
        },
        {
          "match": {
            "path": "container.image",
            "hasPrefix": "docker.io/"
          }
        },
        {
          "match": {
            "path": "container.image",
            "hasPrefix": "ghcr.io/"
          }
        }
      ]
    }
  }
}
```

</details>

### K8S-003: No container may run as privileged

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | One or more containers running in privileged mode |

<details>
<summary>Expression</summary>

```json
{
  "forEach": {
    "path": "spec.containers",
    "as": "container",
    "condition": {
      "any": [
        {
          "match": {
            "path": "container.securityContext.privileged",
            "exists": false
          }
        },
        {
          "match": {
            "path": "container.securityContext.privileged",
            "equals": false
          }
        }
      ]
    }
  }
}
```

</details>
