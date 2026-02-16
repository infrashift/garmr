---
title: "simple-test"
description: "Simple test policy"
sidebar:
  order: 1
---

Simple test policy

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `test` |
| **Enforcement** | `warn` |
| **Rules** | 2 |
| **Targets** | `test` |

## Rules

### TEST-001: Test field exists

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | The 'test' field does not exist |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "test",
    "exists": true
  }
}
```

</details>

### TEST-002: Test field is true

| Property | Value |
|----------|-------|
| **Severity** | `medium` |
| **Message** | The 'test' field is not true |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "test",
    "equals": true
  }
}
```

</details>
