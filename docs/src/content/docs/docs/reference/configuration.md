---
title: "Server Configuration"
description: "Configuration reference for the Garmr server"
sidebar:
  order: 2
  label: "Configuration"
---

Garmr is configured via a YAML configuration file. Copy the example configuration to `config.yaml` and customize it for your environment.

Every setting can also be provided as an environment variable with the `GARMR_` prefix, replacing dots with underscores — for example `GARMR_HTTP_ADDR`, `GARMR_POLICY_DIR`, `GARMR_AUDIT_ENABLED`, `GARMR_AUDIT_PATH`, `GARMR_LOG_LEVEL`.

## Server Address

The server exposes a REST API on port 8080 by default.

```yaml
http_addr: ":8080"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `http_addr` | `:8080` | Address for the HTTP/REST server |

## HTTP Limits & Timeouts

```yaml
max_recv_size: 16777216   # bytes
read_timeout: "30s"
write_timeout: "60s"
idle_timeout: "120s"
shutdown_timeout: "30s"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `max_recv_size` | `16777216` (16 MiB) | Max request body size. Evaluate buffers the whole body before parsing, so this bounds per-request memory — size it together with the container's memory limit (e.g. a 256 MiB limit tolerates only ~16 concurrent max-size requests at the default). Over-limit requests get `413`. |
| `read_timeout` | `30s` | HTTP server read timeout |
| `write_timeout` | `60s` | HTTP server write timeout |
| `idle_timeout` | `120s` | Idle keep-alive connection timeout |
| `shutdown_timeout` | `30s` | Drain budget after SIGTERM |

**Behind a sidecar, reconcile with the proxy's timeouts.** Envoy/Consul
Connect applies its own request and idle timeouts, and whichever side is
shorter wins in ways that are painful to debug (the caller sees the proxy's
error, not Garmr's). Keep `write_timeout` at or above the proxy's request
timeout, and `idle_timeout` above the proxy's idle timeout so connection
reuse isn't broken from the app side.

## Policy Configuration

Specify the directory where Garmr loads policy files (CUE format).

```yaml
policy_dir: "/etc/garmr/policies"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `policy_dir` | _(none)_ | Root directory for CUE policy files |

## Transport Security

Garmr serves plain HTTP only — there are no TLS settings. Transport security, including mTLS, is the service mesh's job: Consul Connect (or another sidecar proxy) terminates mTLS and forwards the verified caller identity in the header configured by `auth.identity_header`. Deploying outside a mesh? Front the server with a TLS-terminating proxy.

## Authentication

Optional API-key authentication for the REST API. When `auth.api_key` is set, all requests (except health endpoints and `/metrics`) must present the key in the configured header or as `Authorization: Bearer <key>`.

```yaml
auth:
  api_key: ""              # empty = authentication disabled
  api_key_header: "X-API-Key"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `auth.api_key` | _(empty — auth disabled)_ | API key clients must present |
| `auth.api_key_header` | `X-API-Key` | Header name used to read the API key |

## Logging

Configure log verbosity and output format. JSON format is recommended for production environments where logs are ingested by a log aggregation system. Console format provides human-readable colored output for development.

```yaml
log:
  level: "info"     # debug, info, warn, error
  format: "json"    # json, console
```

| Setting | Default | Description |
|---------|---------|-------------|
| `log.level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `log.format` | `json` | Output format: `json` or `console` |

## Evaluation Posture

Controls how the engine treats an evaluation that matches zero policies.

```yaml
evaluation:
  require_match: true
```

| Setting | Default | Description |
|---------|---------|-------------|
| `evaluation.require_match` | `true` | When `true`, an evaluation that matches no policies returns `DENY` with a synthetic result explaining why. When `false`, restores the legacy fail-open behavior and returns `ALLOW`. |

Also available as the `--require-match` CLI flag on `garmr-server`.

:::caution
The default changed to fail-closed: prior to this release, an eval with
no matching policies silently returned `ALLOW`. If you rely on that
behavior (for example, evaluating inputs that no policy is expected to
target), set `require_match: false` — but prefer adding a matching
policy over opting out.
:::

## Audit Logging

When enabled, Garmr writes an audit log of all policy evaluation requests and their results. This is useful for compliance, debugging, and security monitoring.

```yaml
audit:
  enabled: true
  path: "/var/log/garmr/audit.log"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `audit.enabled` | `true` | Enable audit logging |
| `audit.path` | `/var/log/garmr/audit.log` | File path for the audit log, or the literal `stdout`/`stderr` to stream records for platform-shipped logging |
| `audit.max_size` / `max_backups` / `max_age` | `100` MB / `10` / `30` days | Rotation (file mode only) |

**In a mesh deployment, prefer `audit.path: stdout`.** The audit trail is
the only record of the mesh-verified `principal`, and a file on local disk
dies with the allocation. Streaming to stdout hands shipping to the
platform's log pipeline (Nomad alloc logs, kubelet, vector/promtail/
fluent-bit) with no sidecar tailer and no rotation to manage; application
logs go to stderr, so the streams stay separable.

## Storage Backend

Garmr reads policies from disk. The filesystem backend is selected
automatically by `policy_dir`, or configured explicitly:

```yaml
storage:
  type: "filesystem"
  root: "/etc/garmr/policies"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `storage.type` | `filesystem` | Backend type (the only implemented backend) |
| `storage.root` | _(from policy_dir)_ | Root directory |

A misconfigured storage backend is fatal at startup: the server refuses to
start rather than silently running without policies.

To serve policies from object storage, sync them onto the pod first — an init
container running `mc mirror` / `aws s3 sync`, or a CSI volume — and point
`root` at the mount.

For more details on storage backends, see the [Storage Backends](/garmr/docs/advanced/storage-backends/) documentation.

## Rate Limiting

Optional token-bucket rate limiting with a global bucket plus per-client
buckets:

```yaml
rate_limit:
  enabled: false
  rps: 100
  burst: 200
  per_client: true
  client_identifier: "ip"     # ip | header | identity
  client_rps: 1000
  client_burst: 100
  max_clients: 10000
  trusted_proxies: []
```

| Setting | Default | Description |
|---------|---------|-------------|
| `rate_limit.enabled` | `false` | Enable rate limiting |
| `rate_limit.rps` / `rate_limit.burst` | `100` / `200` | Global bucket |
| `rate_limit.per_client` | `true` | Track a separate bucket per client |
| `rate_limit.client_identifier` | `ip` | How buckets are keyed: `ip`, `header`, or `identity` |
| `rate_limit.header_name` | `X-Client-ID` | Header read by the `header` identifier |
| `rate_limit.client_rps` / `rate_limit.client_burst` | `1000` / `100` | Each client's bucket |
| `rate_limit.max_clients` | `10000` | Bound on tracked buckets (least-recently-seen eviction) |
| `rate_limit.trusted_proxies` | _(none)_ | CIDRs whose `X-Forwarded-For` is believed in `ip` mode |

**In a service mesh, use `client_identifier: identity`.** Behind a Consul
Connect (or any Envoy) sidecar, every caller's `RemoteAddr` is the local
proxy, so `ip` mode collapses all traffic into a single shared bucket. The
`identity` mode keys buckets on the mesh-verified SPIFFE URI from the XFCC
header (`auth.identity_header`) — the same value the audit log records as
`principal`. Only enable it when a sidecar owns that header; from untrusted
callers it is spoofable, which would let them mint fresh buckets at will.
When the header is absent, `identity` mode falls back to the client IP,
which fails safe (a shared bucket) rather than open.

## Development Mode

Enable development mode for colored console output and relaxed security settings. This should never be enabled in production.

```yaml
# dev: true
```

| Setting | Default | Description |
|---------|---------|-------------|
| `dev` | `false` | Enable development mode with colored console output |

## Complete Example

Below is a complete configuration file showing all available options:

```yaml
# Server address
http_addr: ":8080"

# Policy configuration
policy_dir: "/etc/garmr/policies"

# Graceful shutdown drain budget
shutdown_timeout: "30s"

# HTTP limits (defaults shown; reconcile timeouts with the sidecar proxy)
# max_recv_size: 16777216
# read_timeout: "30s"
# write_timeout: "60s"
# idle_timeout: "120s"

# Authentication & caller identity (optional)
# auth:
#   api_key: "change-me"
#   api_key_header: "X-API-Key"
#   identity_header: "X-Forwarded-Client-Cert"

# CORS (optional; empty list = Access-Control-Allow-Origin: *)
# cors:
#   allowed_origins: []

# Rate limiting (optional; use client_identifier "identity" in a mesh)
# rate_limit:
#   enabled: false
#   rps: 100
#   burst: 200
#   per_client: true
#   client_identifier: "ip"   # ip | header | identity
#   client_rps: 1000
#   client_burst: 100
#   max_clients: 10000
#   trusted_proxies: []

# Logging configuration
log:
  level: "info"
  format: "json"

# Evaluation posture
evaluation:
  require_match: true

# Audit logging
audit:
  enabled: true
  path: "/var/log/garmr/audit.log"
  # max_size: 100      # MB before rotation
  # max_backups: 10
  # max_age: 30        # days

# Storage backend configuration
# storage:
#   type: "filesystem"
#   root: "/etc/garmr/policies"

# Development mode (optional)
# dev: true
```
