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

## OpenAPI Specification

The OpenAPI 3.0 specification is embedded in the server binary (source: `internal/server/openapi.json`) and served at `/openapi.json`. It is not auth-exempt: when `auth.api_key` is set, fetching it requires the key like any other API call.

There is deliberately no bundled Swagger UI page: the server serves machine callers inside an egress-restricted mesh, and the old page loaded its JavaScript from a CDN, which silently broke there. To browse the API interactively, point any local OpenAPI viewer at the spec:

```bash
# Run Swagger UI locally against a running server (without auth.api_key;
# with a key set, save the spec with curl first and point SWAGGER_JSON at it)
docker run --rm -p 8081:8080 -e SWAGGER_JSON_URL=http://localhost:8080/openapi.json swaggerapi/swagger-ui

# Or render the committed spec straight from the repo
npx @redocly/cli preview-docs internal/server/openapi.json
```

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

Requests with a missing or invalid key receive `401 Unauthorized`. Health endpoints (`/health`, `/ready`, `/healthz`, `/readyz`, `/livez`) and `/metrics` are exempt from authentication so probes and scrapers keep working. `/health/deep` and `/openapi.json` are not exempt.

## CORS

Every response carries CORS headers. With `cors.allowed_origins` empty (the
default) the server answers `Access-Control-Allow-Origin: *`; otherwise it
echoes the request's `Origin` when it is on the list. `OPTIONS` preflight
requests are answered `200` with the allow headers before authentication
runs. See [Configuration → CORS](/garmr/docs/reference/configuration/#cors).

Note: the `garmr` CLI does not yet support sending an API key — use the REST API directly against authenticated servers.

---

## Endpoints

### Health Checks

#### GET /healthz and GET /livez

Cheap liveness probes (no dependency checks). Use these for liveness probes.

**Response:** always `200 OK` while the process can answer HTTP. Liveness
status is never changed after startup, so these endpoints report "the process
is up", not "the process is healthy" — use `/readyz` for whether the
instance should get traffic.

```json
{"status": "healthy", "timestamp": "2026-10-04T14:23:04.877Z", "version": "1.2.0"}
```

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/livez
```

---

#### GET /readyz

Readiness probe — runs the in-process readiness checks (with a short timeout)
to determine whether the server can serve traffic.

Readiness checks are deliberately cheap. Checks that make a network round trip
— notably the storage backend — run only on `/health/deep`, because the
kubelet polls this endpoint every few seconds and probing should not generate
external traffic.

**Response:**

- `200 OK` - Server is ready
- `503 Service Unavailable` - Server is not ready (including when zero
  policies are loaded)

```bash
curl http://localhost:8080/readyz
```

---

#### GET /health/deep

Comprehensive health check. Runs every readiness check *plus* the dependency
checks, including a real round trip to the storage backend — in a
shared-volume deployment this is the endpoint that tells you whether the
policy volume is still mounted and readable. Intended for operators and
monitoring, not for probes.

**Response:**

- `200 OK` - Every check healthy (per-check detail in the body)
- `503 Service Unavailable` - One or more checks degraded or unhealthy

Unlike the probe endpoints (`/healthz`, `/readyz`, `/livez`), this endpoint
is **not** auth-exempt: when `auth.api_key` is set, callers must present it.
Probes can't carry credentials; this endpoint performs storage I/O on every
call, so it is deliberately gated.

```bash
curl -f http://localhost:8080/health/deep
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

**GET /ready** returns `{"ready": ..., "checks": ...}` with `200 OK` when ready, `503 Service Unavailable` otherwise. A failing entry in `checks` makes the endpoint report 503, so it agrees with `/readyz`.

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
| `Content-Type` | `application/json` or a YAML type (`application/yaml`, `application/x-yaml`, `text/yaml`); anything else, or none, is auto-detected from the body | No |
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
  "policies": ["container-security"],
  "include_passed": false
}
```

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `input` | object | Resource to evaluate (required) | |
| `namespace` | string | Policy namespace filter | (all) |
| `policies` | []string | Specific policies to evaluate, by **bare** `metadata.name`. Names resolve inside `namespace` (or `default` when `namespace` is empty), so `"security/container-security"` does not match anything. A named policy is still skipped if its target doesn't match the input. | (all matching) |
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
      "description": "Containers must assert runAsNonRoot",
      "severity": "critical",
      "passed": false,
      "message": "containers must set securityContext.runAsNonRoot: true",
      "remediation": "Set securityContext.runAsNonRoot: true and specify a non-root runAsUser"
    }
  ],
  "summary": {
    "total_rules": 6,
    "passed": 5,
    "failed": 1,
    "skipped": 0
  },
  "evaluation_mode": {
    "fail_fast": false,
    "short_circuited": false,
    "total_rules_in_scope": 6,
    "rules_evaluated": 6,
    "rules_skipped": 0,
    "dry_run": false
  },
  "terminated_early": false,
  "metrics": {
    "evaluation_time_ns": 59524,
    "policies_evaluated": 1,
    "rules_evaluated": 6
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `decision` | string | `allow`, `deny`, or `warn` |
| `request_id` | string | Request ID (from header or generated) |
| `results` | []object | Rule evaluation results |
| `summary` | object | Rule outcome counts: `total_rules`, `passed`, `failed`, `skipped` |
| `evaluation_mode` | object | How the evaluation ran, and how much of the rule set it reached |
| `terminated_early` | bool | True when fail-fast stopped the evaluation |
| `termination_rule` | object | The rule that triggered fail-fast; present only when `terminated_early` is true |
| `metrics` | object | Evaluation metrics |

Each entry in `results` carries `policy_name`, `policy_namespace`, `rule_id`,
`description`, `severity`, `passed`, `message`, and `remediation` — the
operator-facing hint for fixing the violation, which `garmr eval` renders
beneath each failure.

A partial evaluation is not the same as a clean one: check
`evaluation_mode.rules_skipped` and `terminated_early` before treating an
`allow` as full coverage.

**System results.** Two failures come from the engine rather than a policy,
and use the reserved `__system__` namespace so they cannot be confused with a
policy verdict:

| `policy_name` | Meaning |
|---------------|---------|
| `policy-match` | No policy targeted the input, and `require_match` is on |
| `policy-timeout` | A policy exceeded `spec.evaluation.timeout`, or could not be evaluated |

Both deny. Rules that never ran are not evidence of compliance.

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

# Evaluate specific policies (bare names, resolved in "namespace")
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "input": {"kind": "Pod", "metadata": {"name": "web"}},
    "namespace": "security",
    "policies": ["container-security"]
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
      "rule_count": 5,
      "hash": "9f2b...c41e"
    }
  ],
  "digest": "1da2206c649e53e18f3a44858694d96c2927e7dd0f064f27934d16066773eb76",
  "instance_id": "a1b2c3d4-alloc"
}
```

`digest` is a deterministic sha256 over the whole loaded policy set. Compare
it with `garmr policy digest <dir>` run on the git checkout to confirm the
server converged on exactly the content that was shipped; `hash` is the
per-policy equivalent.

`instance_id` names the instance that answered. Behind a service-mesh
upstream every call load-balances across instances, so a single response
describes one instance rather than the fleet — collect these across repeated
calls (or use `garmr policy reload --converge`) to verify all of them agree.

**Examples:**

```bash
# List all policies
curl http://localhost:8080/v1/policies

# Filter by namespace
curl http://localhost:8080/v1/policies?namespace=security
```

---

#### DELETE /v1/policies

Remove a loaded policy from the answering instance's memory.

:::caution
This mutates **one** instance — whichever one receives the request — and is
undone by that instance's next reload or restart, which reads the policy back
from storage. To remove a policy for real, delete it from the policy source
(git) and deploy. Use this endpoint only as an emergency, single-instance
override.
:::

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `name` | Policy name |
| `namespace` | Policy namespace (empty means `default`) |

**Response:** always `200 OK`, with whether a policy was actually removed.
A missing or unknown `name` is not an error; it just reports `false`.

```json
{"deleted": true}
```

**Example:**

```bash
curl -X DELETE "http://localhost:8080/v1/policies?name=container-security&namespace=security"
```

---

#### POST /v1/policies/reload

Reload policies from the configured policy source. The new set is compiled
in full and swapped in atomically; if anything fails to load, the reload
returns `500` and the previous set keeps serving. If the server was started
with no policy source, it returns `400`.

**Response:**

```json
{
  "success": true,
  "policies_loaded": 14,
  "digest": "1da2206c649e53e18f3a44858694d96c2927e7dd0f064f27934d16066773eb76",
  "reload_time_ms": 16,
  "storage_type": "filesystem",
  "instance_id": "a1b2c3d4-alloc"
}
```

Reload mutates the one instance that receives the request. `digest` and
`instance_id` are what make a fleet-wide reload verifiable. Use
`garmr policy reload --servers <a>,<b> --expect-digest <d>` to reload every
addressable instance, or `garmr policy reload --converge --instances <n>` to
reload through a mesh upstream that load-balances (see the
[CLI reference](/garmr/docs/guides/cli/#garmr-policy-reload)).

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
  "errors": null,
  "warnings": null
}
```

**Response (invalid):**

```json
{
  "valid": false,
  "errors": [
    {
      "message": "no Policy documents found (expected kind: \"Policy\")",
      "code": "SCHEMA_ERROR"
    }
  ],
  "warnings": null
}
```

Both outcomes return `200 OK`; check `valid`. `warnings` is reserved and is
currently always `null`.

Error objects carry `message` and `code`, plus `line`, `column`, and
`filename` when position information is available. `code` is `PARSE_ERROR`
(not valid CUE), `SCHEMA_ERROR` (does not match the policy schema), or
`COMPILE_ERROR` (matches the schema but the loader would still reject it:
an invalid regex or semver literal, duplicate rule ids, an exception that
matches everything). Validation applies exactly the checks the server runs
when it loads policies.

The request body is capped by `max_validate_size` (default 1 MiB, and never
more than `max_recv_size`); larger bodies get `413`. Concurrent validations
are limited to `min(GOMAXPROCS, 8)`; a request that can't get a slot within
`evaluation.timeout` gets `503`.

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

Every error — regardless of endpoint or status code — returns the same JSON
shape:

```json
{
  "error": "error message"
}
```

**HTTP Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request (malformed body, missing `input`, invalid input, reload with no policy source configured) |
| 401 | Unauthorized (API key configured but missing or wrong) |
| 405 | Method Not Allowed |
| 413 | Request Entity Too Large (body exceeds `max_recv_size`, or `max_validate_size` on `/v1/validate`) |
| 429 | Too Many Requests (rate limited; `Retry-After` and `X-RateLimit-*` headers are set). Probe endpoints and `/metrics` are never rate limited. |
| 500 | Internal Server Error (including a reload that failed — the previous policy set keeps serving) |
| 503 | Service Unavailable: an evaluation that could not start before its budget ran out, or a validation that waited `evaluation.timeout` for a slot (both retryable); also not-ready / unhealthy probe responses |

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

# -f: an HTTP error fails the script instead of yielding an empty "decision"
result=$(curl -sf -X POST "$GARMR_SERVER/v1/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: $REQUEST_ID" \
  -d "{\"input\": $(cat $1), \"namespace\": \"$2\"}")

decision=$(echo "$result" | jq -r '.decision // empty')

echo "Decision: $decision"
echo "Request ID: $REQUEST_ID"

if [ -z "$decision" ]; then
  echo "No decision returned"
  exit 2
fi

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

    // Anything but 200 is a failed evaluation, not a pass.
    if resp.StatusCode != http.StatusOK {
        fmt.Fprintf(os.Stderr, "Error: garmr returned %s\n", resp.Status)
        os.Exit(2)
    }

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(2)
    }

    fmt.Printf("Decision: %s\n", result["decision"])

    switch result["decision"] {
    case "allow", "warn":
    case "deny":
        os.Exit(1)
    default:
        fmt.Fprintln(os.Stderr, "Error: no decision in response")
        os.Exit(2)
    }
}
```

---

## Audit Logging

With audit logging enabled (the default), the server writes one JSON line
per audited operation. `msg` names the event: `decision` (every
`/v1/evaluate`), `validate`, `policy_delete`, and `policy_reload`. Health,
metrics, policy-list and OpenAPI requests are not audited.

A decision record:

```json
{
  "time": "2026-10-04T09:23:16.821633873-05:00",
  "level": "INFO",
  "msg": "decision",
  "request_id": "pipeline-12345",
  "timestamp": "2026-10-04T14:23:16.821629478Z",
  "decision": "deny",
  "namespace": "security",
  "policies_evaluated": 1,
  "rules_evaluated": 6,
  "violations": 6,
  "duration_ms": 0,
  "source_ip": "10.0.0.1:54321",
  "principal": "spiffe://dc1.consul/ns/default/dc/dc1/svc/deployer",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "user_agent": "curl/8.5.0",
  "input_kind": "Pod",
  "input_name": "web"
}
```

`principal` is the URI from the mesh identity header (`auth.identity_header`)
and is empty when no sidecar sets it. `trace_id` is empty when the request
carries no trace context. Every event carries `request_id`, `timestamp`,
`source_ip`, `principal`, and `trace_id`; the other events add their own
fields (`valid`/`error_count` for `validate`, `policy_name`/`deleted` for
`policy_delete`, `success`/`policies_loaded`/`error` for `policy_reload`).

Caller-controlled fields (`request_id`, `user_agent`, `principal`,
`input_kind`, `input_name`, `policy_name`, `policy_namespace`) are cut to 256
bytes and marked `…[truncated]`, keeping each record small enough to be
written atomically when `audit.path` is `stdout`.

Query audit logs by request ID:

```bash
jq 'select(.request_id == "pipeline-12345")' /var/log/garmr/audit.log
```
