---
title: "REST API Reference"
description: "HTTP API endpoints and examples for Garmr"
sidebar:
  order: 1
  label: "REST API"
---

Complete HTTP API reference for Garmr.

## Base URL

```
http://localhost:8080
```

## OpenAPI / Swagger

Interactive API documentation is available at:

- **Swagger UI**: [http://localhost:8080/swagger-ui](http://localhost:8080/swagger-ui)
- **OpenAPI Spec**: [http://localhost:8080/openapi.json](http://localhost:8080/openapi.json)

The OpenAPI 3.0 specification is embedded in the server binary (source: `internal/server/openapi.json`) and served at `/openapi.json` — there is no separate spec file to fetch from the repository.

## Authentication

The server supports optional API-key authentication. It is disabled by default; enable it by starting the server with `--api-key <key>` (config: `auth.api_key`).

When an API key is configured, clients must send it on every request, either:

- In the API key header (default `X-API-Key`, configurable via `--api-key-header` / `auth.api_key_header`):

  ```bash
  curl -H "X-API-Key: $GARMR_API_KEY" http://localhost:8080/v1/policies
  ```

- Or as a bearer token:

  ```bash
  curl -H "Authorization: Bearer $GARMR_API_KEY" http://localhost:8080/v1/policies
  ```

Requests with a missing or invalid key receive `401 Unauthorized`. Health endpoints (`/health`, `/ready`, `/healthz`, `/readyz`, `/livez`) and `/metrics` are exempt from authentication so probes and scrapers keep working.

Note: the `garmr` CLI does not yet support sending an API key — use the REST API directly against authenticated servers.

---

## Endpoints

### Health Checks

#### GET /healthz and GET /livez

Cheap liveness probes (cached status, no dependency checks). Use these for Kubernetes liveness probes.

**Response:**

- `200 OK` - Server process is live
- `503 Service Unavailable` - Server is unhealthy

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/livez
```

---

#### GET /readyz

Readiness probe — runs the health checks (with a short timeout) to determine whether the server can serve traffic.

**Response:**

- `200 OK` - Server is ready
- `503 Service Unavailable` - Server is not ready

```bash
curl http://localhost:8080/readyz
```

---

#### GET /health/deep

Comprehensive health check, including dependency checks such as the storage backend. Intended for debugging and monitoring, not for probes.

```bash
curl http://localhost:8080/health/deep
```

---

#### GET /health and GET /ready (legacy)

Legacy endpoints kept for backwards compatibility.

**GET /health response:**

```json
{
  "healthy": true,
  "version": "0.1.0",
  "uptime": "5m30s"
}
```

**GET /ready** returns `{"ready": ..., "checks": ...}` with `200 OK` when ready, `503 Service Unavailable` otherwise.

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

---

### Metrics

#### GET /metrics

Prometheus metrics endpoint (exempt from authentication).

```bash
curl http://localhost:8080/metrics
```

---

### Policy Evaluation

#### POST /v1/evaluate

Evaluate input against loaded policies.

**Request Headers:**

| Header | Description | Required |
|--------|-------------|----------|
| `Content-Type` | Must be `application/json` | Yes |
| `X-Request-Id` | Request ID for audit correlation | No |

**Request Body:**

```json
{
  "input": {
    "kind": "Pod",
    "metadata": {
      "name": "web-app",
      "namespace": "production"
    },
    "spec": {
      "containers": [...]
    }
  },
  "namespace": "security",
  "policies": ["security/container-security"],
  "trace": false,
  "include_passed": false
}
```

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `input` | object | Resource to evaluate (required) | |
| `namespace` | string | Policy namespace filter | (all) |
| `policies` | []string | Specific policies to evaluate | (all matching) |
| `trace` | bool | Include evaluation trace | `false` |
| `include_passed` | bool | Include passed rules | `false` |

**Response:**

```json
{
  "decision": "deny",
  "request_id": "455ff144-db98-40ba-890b-82b61e0467bd",
  "results": [
    {
      "policy_name": "container-security",
      "policy_namespace": "security",
      "rule_id": "SEC-001",
      "description": "Containers must not run as root",
      "severity": "high",
      "passed": false,
      "message": "Container is running as root"
    }
  ],
  "metrics": {
    "evaluation_time_ns": 5234567,
    "policies_evaluated": 2,
    "rules_evaluated": 8
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `decision` | string | `allow`, `deny`, or `warn` |
| `request_id` | string | Request ID (from header or generated) |
| `results` | []object | Rule evaluation results |
| `metrics` | object | Evaluation metrics |

**Response Headers:**

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Request ID (echoed or generated) |

**Examples:**

```bash
# Basic evaluation
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "kind": "Pod",
      "metadata": {"name": "web"}
    }
  }'

# With namespace filter
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {"kind": "Pod", "metadata": {"name": "web"}},
    "namespace": "security"
  }'

# With request ID for audit correlation
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: pipeline-12345" \
  -d '{
    "input": {"kind": "Pod", "metadata": {"name": "web"}}
  }'

# Include passed rules
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {"kind": "Pod", "metadata": {"name": "web"}},
    "include_passed": true
  }'

# Evaluate specific policies
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {"kind": "Pod", "metadata": {"name": "web"}},
    "policies": ["security/container-security"]
  }'
```

---

### Policy Management

#### GET /v1/policies

List loaded policies.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `namespace` | Filter by namespace |

**Response:**

```json
{
  "policies": [
    {
      "name": "container-security",
      "namespace": "security",
      "rule_count": 5
    }
  ]
}
```

**Examples:**

```bash
# List all policies
curl http://localhost:8080/v1/policies

# Filter by namespace
curl http://localhost:8080/v1/policies?namespace=security
```

---

#### DELETE /v1/policies

Delete a loaded policy by name and namespace.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Policy name (required) |
| `namespace` | Policy namespace |

**Example:**

```bash
curl -X DELETE "http://localhost:8080/v1/policies?name=container-security&namespace=security"
```

---

#### POST /v1/policies/reload

Reload policies from disk (hot reload).

**Response:**

```json
{
  "success": true,
  "policies_loaded": 14,
  "reload_time_ms": 16,
  "storage_type": "filesystem"
}
```

**Example:**

```bash
curl -X POST http://localhost:8080/v1/policies/reload
```

---

### Policy Validation

#### POST /v1/validate

Validate a policy without loading it.

**Request Body:**

```json
{
  "policy": "package test\n\nmyPolicy: {\n  apiVersion: \"policy.garmr.io/v1\"\n  ...\n}"
}
```

**Response (valid):**

```json
{
  "valid": true,
  "warnings": []
}
```

**Response (invalid):**

```json
{
  "valid": false,
  "errors": [
    {
      "message": "undefined field: spec.rulz",
      "code": "SCHEMA_ERROR"
    }
  ],
  "warnings": []
}
```

Error objects carry `message` and `code`, plus `line`, `column`, and
`filename` when position information is available.

**Example:**

```bash
curl -X POST http://localhost:8080/v1/validate \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "package test\n\nmyPolicy: { apiVersion: \"policy.garmr.io/v1\" }"
  }'
```

---

## Error Responses

All errors return a JSON response:

```json
{
  "error": "error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

**HTTP Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request (invalid input) |
| 404 | Not Found |
| 500 | Internal Server Error |

---

## Examples with Test Data

### Evaluate Secure Pod

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"input\": $(cat testdata/real-world/k8s-pod-security-context-pass.json)}"
```

### Evaluate Insecure Pod

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"input\": $(cat testdata/real-world/k8s-pod-security-context-fail.yml | yq -o json), \"namespace\": \"security\"}"
```

### Evaluate Release Artifact

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: release-v1.2.3" \
  -d "{\"input\": $(cat testdata/real-world/release-pass.json), \"namespace\": \"release\"}"
```

---

## CI/CD Integration

### Shell Script

```bash
#!/bin/bash
set -e

GARMR_SERVER="${GARMR_SERVER:-http://localhost:8080}"
REQUEST_ID="${CI_JOB_ID:-local-$(date +%s)}"

result=$(curl -s -X POST "$GARMR_SERVER/v1/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: $REQUEST_ID" \
  -d "{\"input\": $(cat $1), \"namespace\": \"$2\"}")

decision=$(echo "$result" | jq -r '.decision')

echo "Decision: $decision"
echo "Request ID: $REQUEST_ID"

if [ "$decision" = "deny" ]; then
  echo "Violations:"
  echo "$result" | jq -r '.results[] | select(.passed == false) | "  - \(.rule_id): \(.message)"'
  exit 1
fi
```

### Python

```python
import requests
import os
import sys
import json

GARMR_SERVER = os.environ.get('GARMR_SERVER', 'http://localhost:8080')
REQUEST_ID = os.environ.get('CI_JOB_ID', 'local-test')

def evaluate(input_data, namespace=None):
    payload = {'input': input_data}
    if namespace:
        payload['namespace'] = namespace

    response = requests.post(
        f'{GARMR_SERVER}/v1/evaluate',
        json=payload,
        headers={
            'Content-Type': 'application/json',
            'X-Request-Id': REQUEST_ID
        }
    )
    response.raise_for_status()
    return response.json()

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        input_data = json.load(f)

    result = evaluate(input_data, namespace='security')

    print(f"Decision: {result['decision']}")

    if result['decision'] == 'deny':
        for r in result['results']:
            if not r['passed']:
                print(f"  - {r['rule_id']}: {r['message']}")
        sys.exit(1)
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
)

func main() {
    server := os.Getenv("GARMR_SERVER")
    if server == "" {
        server = "http://localhost:8080"
    }

    input := map[string]interface{}{
        "kind": "Pod",
        "metadata": map[string]interface{}{
            "name": "web",
        },
    }

    payload, _ := json.Marshal(map[string]interface{}{
        "input":     input,
        "namespace": "security",
    })

    req, _ := http.NewRequest("POST", server+"/v1/evaluate", bytes.NewReader(payload))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Request-Id", os.Getenv("CI_JOB_ID"))

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)

    fmt.Printf("Decision: %s\n", result["decision"])

    if result["decision"] == "deny" {
        os.Exit(1)
    }
}
```

---

## Audit Log Correlation

Every request is logged to the audit log with:

```json
{
  "request_id": "pipeline-12345",
  "timestamp": "2024-12-07T06:00:00Z",
  "decision": "deny",
  "namespace": "security",
  "policies_evaluated": 2,
  "rules_evaluated": 8,
  "violations": 3,
  "duration_ms": 5,
  "source_ip": "10.0.0.1:54321",
  "user_agent": "curl/7.68.0",
  "input_kind": "Pod",
  "input_name": "web-app"
}
```

Query audit logs by request ID:

```bash
cat /var/log/garmr/audit.log | jq 'select(.request_id == "pipeline-12345")'
```
