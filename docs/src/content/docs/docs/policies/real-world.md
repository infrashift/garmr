---
title: "Real-World Policy Examples"
description: "Production-ready policy patterns and examples"
sidebar:
  order: 0
  label: "Real-World Examples"
---

Production-ready policy examples with user stories and usage instructions.

## Overview

| Policy | Use Case | Enforcement |
|--------|----------|-------------|
| Container Security | Kubernetes container hardening | deny |
| Release Gate | CI/CD production release | deny |
| Staging Gate | Pre-production checks | warn |
| Certificate Management | TLS lifecycle | deny |
| Resource Governance | Cloud standardization | deny |

## Input Formats

Both JSON and YAML input formats are supported. YAML is particularly useful for Kubernetes manifests and other infrastructure-as-code files.

```bash
# JSON input
garmr eval --input deployment.json -n real-world

# YAML input (auto-detected from extension)
garmr eval --input deployment.yaml -n real-world

# YAML with explicit format
garmr eval --input deployment.txt --format yaml -n real-world
```

## Enforcement Actions

- **deny**: Block deployment on rule failure (exit code 1)
- **warn**: Log warning, allow deployment (exit code 0, or 2 with `--fail-on-warn`)
- **audit**: Log only, always allow (exit code 0)

---

## Container Security Policy

### User Story

> As a Platform Engineer, I want to ensure all containers meet security best practices to minimize attack surface and maintain SOC2 compliance.

**Policy:** `example-policies/real-world/container-security.cue`

**Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| SEC-001 | critical | Containers must not run as root |
| SEC-002 | critical | No privileged containers |
| SEC-003 | high | Read-only root filesystem |
| SEC-004 | high | Resource limits required |
| SEC-005 | critical | Approved registries only |
| SEC-006 | high | No :latest tags |

### Test Data

**JSON:**
- Pass: `test-data/real-world/container-security-pass.json`
- Fail: `test-data/real-world/container-security-fail.json`

**YAML:**
- Pass: `test-data/real-world/container-security-pass.yaml`
- Fail: `test-data/real-world/container-security-fail.yaml`

### CLI Examples (JSON)

```bash
# Secure pod - should ALLOW
garmr eval --input test-data/real-world/container-security-pass.json -n real-world

# Insecure pod - should DENY
garmr eval --input test-data/real-world/container-security-fail.json -n real-world

# View violations in JSON
garmr eval --input test-data/real-world/container-security-fail.json -n real-world -o json | \
  jq '.results[] | select(.passed==false) | {id: .rule_id, severity: .severity, message: .message}'
```

### CLI Examples (YAML)

```bash
# Secure pod - should ALLOW (native Kubernetes YAML)
garmr eval --input test-data/real-world/container-security-pass.yaml -n real-world

# Insecure pod - should DENY
garmr eval --input test-data/real-world/container-security-fail.yaml -n real-world

# Evaluate actual Kubernetes manifests
garmr eval --input k8s/deployments/web-app.yaml -n real-world
```

### curl Examples (JSON)

```bash
# Secure pod - should return {"decision": "allow"}
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"input\": $(cat test-data/real-world/container-security-pass.json), \"namespace\": \"real-world\"}" \
  | jq '.decision'
```

### curl Examples (YAML)

```bash
# Secure pod with YAML - should return {"decision": "allow"}
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/x-yaml" \
  -d '
input:
  kind: pod
  apiVersion: v1
  metadata:
    name: secure-web-app
  spec:
    containers:
      - name: app
        image: gcr.io/my-project/web-app:v2.1.0
        resources:
          limits:
            memory: 512Mi
            cpu: 500m
        securityContext:
          runAsNonRoot: true
          privileged: false
          readOnlyRootFilesystem: true
namespace: real-world
' | jq '.decision'
```

---

## Release Gate Policy

### User Story

> As a Release Manager, I want to enforce quality gates before production releases to ensure all artifacts meet testing, security, and approval requirements.

**Policy:** `example-policies/real-world/release-gate.cue`

**Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| REL-001 | critical | All tests must pass |
| REL-002 | high | Coverage >= 80% |
| REL-003 | critical | Security scan passed |
| REL-004 | high | Version >= 1.0.0 |
| REL-005 | critical | No pre-release versions |
| REL-006 | high | Approval required |

### Test Data

- **Pass:** `test-data/real-world/release-gate-pass.json`
- **Fail:** `test-data/real-world/release-gate-fail.json`

### CLI Examples

```bash
# Valid release - should ALLOW
garmr eval --input test-data/real-world/release-gate-pass.json -n real-world

# Invalid release - should DENY
garmr eval --input test-data/real-world/release-gate-fail.json -n real-world

# CI/CD integration with request ID
garmr eval --input test-data/real-world/release-gate-pass.json \
  -n real-world \
  --request-id "release-${VERSION}" \
  -o json
```

### curl Examples

```bash
# Production release check
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: release-v2.1.0" \
  -d "{\"input\": $(cat test-data/real-world/release-gate-pass.json), \"namespace\": \"real-world\"}" \
  | jq '{decision, request_id}'
```

---

## Staging Gate Policy (WARN)

### User Story

> As a Developer, I want advisory feedback on staging deployments without blocking the pipeline, so I can see issues before they become blockers.

**Policy:** `example-policies/real-world/release-gate.cue` (stagingGatePolicy)

**Enforcement:** `warn`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| STG-001 | medium | Coverage >= 70% (advisory) |
| STG-002 | low | Documentation present (advisory) |

### WARN Behavior

With `enforcement: action: "warn"`:

- CLI returns exit code 0 (success) even with rule violations
- Violations are logged and returned in response
- Use `--fail-on-warn` to treat warnings as failures (exit code 2)

### CLI Examples

```bash
# WARN enforcement - returns exit code 0 even with violations
garmr eval --input test-data/real-world/release-gate-fail.json -n real-world
echo "Exit code: $?"  # 0

# Treat warnings as failures
garmr eval --input test-data/real-world/release-gate-fail.json -n real-world --fail-on-warn
echo "Exit code: $?"  # 2 if warnings present
```

---

## Certificate Management Policy

### User Story

> As a Security Engineer, I want to ensure TLS certificates meet security standards and are renewed before expiration to maintain compliance.

**Policy:** `example-policies/real-world/certificate-management.cue`

**Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| CERT-001 | critical | Not expired |
| CERT-002 | high | Valid for 30+ days |
| CERT-003 | critical | Key size >= 2048 bits |
| CERT-004 | high | Approved signature algorithm |

### Test Data

- **Pass:** `test-data/real-world/certificate-pass.json`
- **Fail:** `test-data/real-world/certificate-fail.json`

### CLI Examples

```bash
# Valid certificate - should ALLOW
garmr eval --input test-data/real-world/certificate-pass.json -n real-world

# Expired certificate - should DENY
garmr eval --input test-data/real-world/certificate-fail.json -n real-world
```

### curl Examples

```bash
# Check certificate compliance
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"input\": $(cat test-data/real-world/certificate-pass.json), \"namespace\": \"real-world\"}" \
  | jq '.decision'
```

---

## Certificate Warning Policy (WARN)

### User Story

> As an Operations Engineer, I want proactive alerts when certificates are approaching expiration so I can plan renewals.

**Policy:** `example-policies/real-world/certificate-management.cue` (certificateWarningPolicy)

**Enforcement:** `warn`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| CERTWARN-001 | low | Expires within 90 days |
| CERTWARN-002 | medium | Expires within 60 days |

### Proactive Monitoring

```bash
# Check all certificates for upcoming expiration
for cert in certs/*.json; do
  result=$(garmr eval --input "$cert" -n real-world -o json)
  warnings=$(echo "$result" | jq '[.results[] | select(.passed==false)] | length')
  if [ "$warnings" -gt 0 ]; then
    echo "ATTENTION: $cert has expiration warnings"
    echo "$result" | jq '.results[] | select(.passed==false) | .message'
  fi
done
```

---

## Resource Governance Policy

### User Story

> As a FinOps Engineer, I want to enforce naming conventions, required labels, and resource limits to maintain cost visibility and standardization.

**Policy:** `example-policies/real-world/resource-governance.cue`

**Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| GOV-001 | medium | DNS naming convention |
| GOV-002 | high | Required labels (app, env, team) |
| GOV-003 | medium | Valid environment label |
| GOV-004 | high | Max 20 replicas |

### Test Data

- **Pass:** `test-data/real-world/resource-governance-pass.json`
- **Fail:** `test-data/real-world/resource-governance-fail.json`

### CLI Examples

```bash
# Compliant resource - should ALLOW
garmr eval --input test-data/real-world/resource-governance-pass.json -n real-world

# Non-compliant resource - should DENY
garmr eval --input test-data/real-world/resource-governance-fail.json -n real-world

# Show all violations
garmr eval --input test-data/real-world/resource-governance-fail.json -n real-world -o json | \
  jq '.results[] | select(.passed==false) | {rule: .rule_id, message: .message}'
```

---

## CI/CD Integration Example

### GitHub Actions

```yaml
name: Policy Check
on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Evaluate Container Security
        run: |
          garmr eval --input k8s/deployment.json \
            -n real-world \
            --request-id "gh-${{ github.run_id }}" \
            -o json > policy-result.json

          decision=$(jq -r '.decision' policy-result.json)
          if [ "$decision" = "deny" ]; then
            echo "::error::Policy check failed"
            jq '.results[] | select(.passed==false)' policy-result.json
            exit 1
          fi
```

### GitLab CI

```yaml
policy-check:
  stage: validate
  script:
    - |
      garmr eval --input k8s/deployment.json \
        -n real-world \
        --request-id "gl-${CI_PIPELINE_ID}" \
        -o json > policy-result.json

      if [ "$(jq -r '.decision' policy-result.json)" = "deny" ]; then
        echo "Policy violations found:"
        jq '.results[] | select(.passed==false) | "\(.rule_id): \(.message)"' policy-result.json
        exit 1
      fi
  artifacts:
    paths:
      - policy-result.json
```

---

## Severity Guidelines

| Severity | When to Use | Example |
|----------|-------------|---------|
| critical | Security vulnerabilities, compliance violations | Privileged containers, expired certs |
| high | Production stability risks | Missing resource limits |
| medium | Best practice violations | Naming conventions |
| low | Minor issues | Missing optional labels |
| info | Recommendations | Documentation suggestions |

---

## Running All Real-World Tests

```bash
# Start server
make run

# Test all real-world policies
echo "=== Container Security ==="
garmr eval --input test-data/real-world/container-security-pass.json -n real-world
garmr eval --input test-data/real-world/container-security-fail.json -n real-world

echo "=== Release Gate ==="
garmr eval --input test-data/real-world/release-gate-pass.json -n real-world
garmr eval --input test-data/real-world/release-gate-fail.json -n real-world

echo "=== Certificate Management ==="
garmr eval --input test-data/real-world/certificate-pass.json -n real-world
garmr eval --input test-data/real-world/certificate-fail.json -n real-world

echo "=== Resource Governance ==="
garmr eval --input test-data/real-world/resource-governance-pass.json -n real-world
garmr eval --input test-data/real-world/resource-governance-fail.json -n real-world
```
