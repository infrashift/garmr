---
title: "Real-World Policy Examples"
description: "Production-ready policy patterns and examples"
sidebar:
  order: 0
  label: "Real-World Examples"
---

Production-ready policy examples with user stories and usage instructions.

## Overview

| Policy | Namespace | Use Case | Enforcement |
|--------|-----------|----------|-------------|
| Container Security | `security` | Kubernetes container hardening | deny |
| Release Gate | `release` | CI/CD production release (critical rules) | deny |
| Release Advisory | `release` | Non-critical release-quality signals | warn |
| Certificate Management | `security` | TLS lifecycle | deny |
| Cloud Resource Governance | `cloud-governance` | Cloud standardization | deny |
| Cloud Resource Governance (Terraform) | `cloud-governance` | Terraform plan governance | deny |

## Input Formats

Both JSON and YAML input formats are supported. YAML is particularly useful for Kubernetes manifests and other infrastructure-as-code files.

```bash
# JSON input
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security

# YAML input (auto-detected from extension)
garmr eval --input testdata/real-world/k8s-pod-security-context-fail.yml -n security

# YAML with explicit format
garmr eval --input deployment.txt --format yaml -n security
```

## Enforcement Actions

- **deny**: Block deployment on rule failure (exit code 1)
- **warn**: Log warning, allow deployment (exit code 0)
- **audit**: Log only, always allow (exit code 0)

---

## Container Security Policy

### User Story

> As a Platform Engineer, I want to ensure all containers meet security best practices to minimize attack surface and maintain SOC2 compliance.

**Policy:** `example-policies/real-world/container-security.cue`

**Namespace:** `security` — **Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| SEC-001 | critical | Containers must assert runAsNonRoot |
| SEC-002 | critical | Containers must not use privileged mode |
| SEC-003 | high | Container images must use specific tags, not latest |
| SEC-004 | critical | Container images must come from approved registry |
| SEC-005 | high | All containers must have resource limits |
| SEC-006 | medium | Read-only root filesystem should be enabled |

### Test Data

- Pass: `testdata/real-world/k8s-pod-security-context-pass.json`
- Fail: `testdata/real-world/k8s-pod-security-context-fail.yml`

### CLI Examples

```bash
# Secure pod - should ALLOW
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security

# Insecure pod (YAML input) - should DENY
garmr eval --input testdata/real-world/k8s-pod-security-context-fail.yml -n security

# View violations in JSON
garmr eval --input testdata/real-world/k8s-pod-security-context-fail.yml -n security -o json | \
  jq '.results[] | select(.passed==false) | {id: .rule_id, severity: .severity, message: .message}'

# Evaluate actual Kubernetes manifests
garmr eval --input k8s/deployments/web-app.yaml -n security
```

### curl Examples (JSON)

```bash
# Secure pod - should return "allow"
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"input\": $(cat testdata/real-world/k8s-pod-security-context-pass.json), \"namespace\": \"security\"}" \
  | jq '.decision'
```

### curl Examples (YAML)

```bash
# Secure pod with YAML - should return "allow"
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
namespace: security
' | jq '.decision'
```

---

## Release Gate Policy

### User Story

> As a Release Manager, I want to enforce quality gates before production releases to ensure all artifacts meet testing, security, and approval requirements.

**Policy:** `example-policies/real-world/release-gate.cue` (`release-gate`)

**Namespace:** `release` — **Enforcement:** `deny` (critical-severity rules)

The policy file defines a shared rule set. The `release-gate` policy denies on the critical rules; the `release-advisory` policy (below) warns on the rest.

| Rule ID | Severity | Description |
|---------|----------|-------------|
| REL-001 | critical | Release version must be valid semver |
| REL-002 | critical | All tests must pass |
| REL-003 | high | Code coverage must be at least 80% |
| REL-004 | critical | No critical or high vulnerabilities |
| REL-005 | high | Build must have signed provenance |
| REL-006 | high | Target environment must be valid DTAP stage |
| REL-007 | critical | Approval is required for production releases |

### Test Data

- **Pass:** `testdata/real-world/release-pass.json` (also `release-pass.yml`)
- **Fail (advisory only):** `testdata/real-world/release-fail-1.yml`
- **Fail (critical + advisory):** `testdata/real-world/release-fail-3.json`
- **Fail (everything):** `testdata/real-world/release-fail-all.json`

### CLI Examples

```bash
# Valid release - should ALLOW
garmr eval --input testdata/real-world/release-pass.json -n release

# Invalid release - should DENY
garmr eval --input testdata/real-world/release-fail-3.json -n release

# CI/CD integration with request ID
garmr eval --input testdata/real-world/release-pass.json \
  -n release \
  --request-id "release-${VERSION}" \
  -o json
```

### curl Examples

```bash
# Production release check
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: release-v2.1.0" \
  -d "{\"input\": $(cat testdata/real-world/release-pass.json), \"namespace\": \"release\"}" \
  | jq '{decision, request_id}'
```

---

## Release Advisory Policy (WARN)

### User Story

> As a Developer, I want advisory feedback on release-quality issues without blocking the pipeline, so I can see issues before they become blockers.

**Policy:** `example-policies/real-world/release-gate.cue` (`release-advisory`)

**Namespace:** `release` — **Enforcement:** `warn` (non-critical rules: REL-003, REL-005, REL-006)

### WARN Behavior

With `enforcement: action: "warn"`:

- CLI returns exit code 0 (success) even with rule violations
- Violations are logged and returned in response
- To make warnings block CI, change the policy to `enforcement: action: "deny"` — the gating decision belongs in the policy, not in client flags.

### CLI Examples

```bash
# Only advisory rules fail - decision is WARN, exit code 0
garmr eval --input testdata/real-world/release-fail-1.yml -n release
echo "Exit code: $?"  # 0
```

---

## Certificate Management Policy

### User Story

> As a Security Engineer, I want to ensure TLS certificates meet security standards and are renewed before expiration to maintain compliance.

**Policy:** `example-policies/real-world/certificate-management.cue`

**Namespace:** `security` — **Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| CERT-001 | critical | Certificate must not be expired |
| CERT-002 | high | Certificate must have at least 30 days remaining |
| CERT-003 | critical | Certificate key size must be at least 2048 bits |
| CERT-004 | high | Certificate must use approved signature algorithm |
| CERT-005 | medium | Certificate must include Subject Alternative Names |
| CERT-006 | medium | Wildcard certificates are discouraged in production |

### CLI Examples

No dedicated test-data files ship for this policy; pass certificate metadata inline:

```bash
# Valid certificate - should ALLOW
garmr eval -n security -d '{
  "kind": "Certificate",
  "metadata": {"name": "web-tls"},
  "spec": {
    "commonName": "web.example.com",
    "notAfter": "2030-01-01T00:00:00Z",
    "keySize": 4096,
    "signatureAlgorithm": "SHA256WithRSA",
    "subjectAlternativeNames": ["web.example.com"]
  }
}'

# Expired certificate with weak key - should DENY
garmr eval -n security -d '{
  "kind": "Certificate",
  "metadata": {"name": "old-tls"},
  "spec": {
    "commonName": "old.example.com",
    "notAfter": "2024-01-01T00:00:00Z",
    "keySize": 1024,
    "signatureAlgorithm": "SHA1WithRSA"
  }
}'
```

### Proactive Monitoring

```bash
# Check all certificates for upcoming expiration
for cert in certs/*.json; do
  result=$(garmr eval --input "$cert" -n security -o json)
  warnings=$(echo "$result" | jq '[.results[] | select(.passed==false)] | length')
  if [ "$warnings" -gt 0 ]; then
    echo "ATTENTION: $cert has certificate violations"
    echo "$result" | jq '.results[] | select(.passed==false) | .message'
  fi
done
```

---

## Cloud Resource Governance Policy

### User Story

> As a FinOps Engineer, I want to enforce required labels, approved instance types, and resource limits to maintain cost visibility and standardization.

**Policy:** `example-policies/real-world/cloud-resource-governance.cue`

**Namespace:** `cloud-governance` — **Enforcement:** `deny`

| Rule ID | Severity | Description |
|---------|----------|-------------|
| GOV-001 | high | All resources must have an owner label |
| GOV-002 | medium | All resources must have a cost-center label |
| GOV-003 | high | Instance type must be from approved list |
| GOV-004 | medium | Auto-scaling must have reasonable bounds |
| GOV-005 | medium | Storage volumes must not exceed 500 GB |
| GOV-006 | high | Resources must have a valid environment tag |

A Terraform-plan variant lives in `example-policies/real-world/cloud-resource-governance-terraform.cue` (rules TF-001 through TF-006, same namespace).

### Test Data

- **Pass:** `testdata/real-world/cloud-resource-governance-pass.json`
- **Fail:** `testdata/real-world/cloud-resource-governance-fail.json`
- **Terraform pass/fail:** `testdata/real-world/cloud-resource-governance-terraform-pass.json`, `cloud-resource-governance-terraform-fail.json`

### CLI Examples

```bash
# Compliant resource - should ALLOW
garmr eval --input testdata/real-world/cloud-resource-governance-pass.json -n cloud-governance

# Non-compliant resource - should DENY
garmr eval --input testdata/real-world/cloud-resource-governance-fail.json -n cloud-governance

# Show all violations
garmr eval --input testdata/real-world/cloud-resource-governance-fail.json -n cloud-governance -o json | \
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
            -n security \
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
        -n security \
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
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security
garmr eval --input testdata/real-world/k8s-pod-security-context-fail.yml -n security

echo "=== Release Gate + Advisory ==="
garmr eval --input testdata/real-world/release-pass.json -n release
garmr eval --input testdata/real-world/release-fail-1.yml -n release
garmr eval --input testdata/real-world/release-fail-3.json -n release
garmr eval --input testdata/real-world/release-fail-all.json -n release

echo "=== Cloud Resource Governance ==="
garmr eval --input testdata/real-world/cloud-resource-governance-pass.json -n cloud-governance
garmr eval --input testdata/real-world/cloud-resource-governance-fail.json -n cloud-governance
garmr eval --input testdata/real-world/cloud-resource-governance-terraform-pass.json -n cloud-governance
garmr eval --input testdata/real-world/cloud-resource-governance-terraform-fail.json -n cloud-governance
```
