---
title: "prod-gate"
description: "Production environment gate - strictest requirements"
sidebar:
  order: 3
---

Production environment gate - strictest requirements

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | `release` |
| **Enforcement** | `deny` |
| **Rules** | 6 |
| **Targets** | `deployment`, `release` |

### Labels

| Key | Value |
|-----|-------|
| `environment` | `prod` |

## Rules

### PRD-001: All tests must pass

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Tests have not passed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "tests.passed",
    "equals": true
  }
}
```

</details>

### PRD-002: Code coverage minimum 80%

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Code coverage below 80% |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "coverage",
    "greaterThanOrEqual": 80
  }
}
```

</details>

### PRD-003: No critical security issues

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Critical security findings detected |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "security.criticalFindings",
    "equals": 0
  }
}
```

</details>

### PRD-004: No high security issues

| Property | Value |
|----------|-------|
| **Severity** | `high` |
| **Message** | Too many high severity findings |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "security.highFindings",
    "lessThan": 5
  }
}
```

</details>

### PRD-005: Artifact must be signed

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | Artifact is not signed |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "artifact.signed",
    "equals": true
  }
}
```

</details>

### PRD-006: Approval required

| Property | Value |
|----------|-------|
| **Severity** | `critical` |
| **Message** | No approvals found |

<details>
<summary>Expression</summary>

```json
{
  "match": {
    "path": "approvals",
    "exists": true
  }
}
```

</details>
