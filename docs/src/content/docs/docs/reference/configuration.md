---
title: "Server Configuration"
description: "Configuration reference for the Garmr server"
sidebar:
  order: 2
  label: "Configuration"
---

Garmr is configured via a YAML configuration file. Copy the example configuration to `config.yaml` and customize it for your environment.

`garmr-server` reads the file named by `--config`. Without that flag it looks
for `config.yaml` in `/etc/garmr`, then `$HOME/.garmr`, then the working
directory, and starts on defaults if none exists.

Settings resolve in this order, highest first: command-line flag,
environment variable, config file, built-in default. Every setting can be
provided as an environment variable with the `GARMR_` prefix, replacing dots
with underscores — for example `GARMR_HTTP_ADDR`, `GARMR_POLICY_DIR`,
`GARMR_AUDIT_ENABLED`, `GARMR_AUDIT_PATH`, `GARMR_LOG_LEVEL`. Each setting's
flag is listed in [Command-Line Flags](#command-line-flags).

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
max_recv_size: 16777216      # bytes
max_validate_size: 1048576   # bytes
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
| `max_validate_size` | `1048576` (1 MiB) | Max CUE source accepted by `/v1/validate`. Deliberately far below `max_recv_size`: validation compiles caller-supplied source, and unification cost grows with the source's disjunctions rather than its length. The effective cap is the smaller of this and `max_recv_size`. |
| `shutdown_timeout` | `30s` | Drain budget after SIGTERM |

`write_timeout` expires the *connection*; it does not cancel the handler. The
bound that actually stops work is `evaluation.timeout` (below).

**Behind a sidecar, reconcile with the proxy's timeouts.** Envoy/Consul
Connect applies its own request and idle timeouts, and whichever side is
shorter wins in ways that are painful to debug (the caller sees the proxy's
error, not Garmr's). Keep `write_timeout` at or above the proxy's request
timeout, and `idle_timeout` above the proxy's idle timeout so connection
reuse isn't broken from the app side.

## Evaluation Limits

```yaml
evaluation:
  timeout: "10s"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `evaluation.timeout` | `10s` | Max time for one `/v1/evaluate` request. For `/v1/validate` it bounds only the wait for a validation slot, not the compilation itself. |

For evaluation, this is the only limit that actually stops work.
`write_timeout` expires the connection without cancelling the handler, and a
policy's own `spec.evaluation.timeout` is optional and unset by default — so
without this, a request that had already lost its client went on running and
holding its decoded input. Validation is different: once a request holds a
slot, compiling its source is not interruptible, which is why
`max_validate_size` caps the source instead.

Evaluations have no pool and no queue: every request runs immediately, in
parallel, against the loaded policy set. A request whose budget expires
while its rules are running is denied with a synthetic timeout result
(`__system__/policy-timeout`). A request whose context has already ended
before evaluation starts gets `503` (retry is meaningful). `/v1/validate`
compiles caller-supplied CUE, so it is bounded by a concurrency gate of
`min(GOMAXPROCS, 8)`. A validate request whose budget expires while waiting
for that gate is rejected with `503`.

**Keep this below the sidecar's request timeout** so Garmr, not the proxy,
decides the outcome — otherwise the caller gets the proxy's `504` and no
digest or error detail from Garmr.

## Policy Configuration

Specify the directory where Garmr loads policy files (CUE format).

```yaml
policy_dir: "/etc/garmr/policies"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `policy_dir` | _(none)_ | Root directory for CUE policy files. Ignored when `storage.type` is set. |

With neither `policy_dir` nor `storage.type` set, there is no policy
source: the server starts with zero policies (so, under the default
`require_match: true`, it denies every evaluation) and
`POST /v1/policies/reload` returns `400 No policy source configured`.

## Transport Security

Garmr serves plain HTTP only — there are no TLS settings. Transport security, including mTLS, is the service mesh's job: Consul Connect (or another sidecar proxy) terminates mTLS and forwards the verified caller identity in the header configured by `auth.identity_header`. Deploying outside a mesh? Front the server with a TLS-terminating proxy.

## Authentication

Optional API-key authentication for the REST API. When `auth.api_key` is set, every request must present the key in the configured header or as `Authorization: Bearer <key>`, except the probe endpoints (`/health`, `/ready`, `/healthz`, `/readyz`, `/livez`) and `/metrics`. `/health/deep` and `/openapi.json` are **not** exempt.

```yaml
auth:
  api_key: ""              # empty = authentication disabled
  api_key_header: "X-API-Key"
  identity_header: "X-Forwarded-Client-Cert"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `auth.api_key` | _(empty — auth disabled)_ | API key clients must present |
| `auth.api_key_header` | `X-API-Key` | Header name used to read the API key |
| `auth.identity_header` | `X-Forwarded-Client-Cert` | Header carrying the mesh-verified caller identity (XFCC format). Its URI (SPIFFE ID) becomes the audit record's `principal` and the key for `rate_limit.client_identifier: identity`. Only trustworthy when a sidecar sets it. |

## CORS

```yaml
cors:
  allowed_origins: []   # empty = Access-Control-Allow-Origin: *
```

| Setting | Default | Description |
|---------|---------|-------------|
| `cors.allowed_origins` | _(empty)_ | Origins echoed back in `Access-Control-Allow-Origin`. Empty allows every origin (`*`); an entry of `*` allows any origin that sends an `Origin` header. |

Every response carries `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
and `Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-Id, X-API-Key`.
`OPTIONS` preflights are answered `200` before authentication runs, so they
never need the API key. Browser clients using a custom `api_key_header` should
send `Authorization: Bearer <key>` instead, since only `X-API-Key` is in the
allowed-headers list.

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

When enabled, Garmr writes one JSON record per audited operation: every
evaluation decision (`decision`), every `/v1/validate` call (`validate`),
every `DELETE /v1/policies` (`policy_delete`), and every reload, successful
or not (`policy_reload`). Each record carries the request ID, source IP,
mesh `principal` and trace ID; see the [REST API audit
section](/garmr/docs/guides/rest-api/#audit-logging) for the record shape.
Caller-controlled fields (request ID, user agent, principal, input kind and
name, policy name and namespace) are truncated to 256 bytes with a
`…[truncated]` marker, so one oversized header can't push a record past the
size at which a pipe write stays atomic.

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

In file mode the server creates the parent directory at startup and refuses
to start if it can't. The default `/var/log/garmr` is usually not writable by
a non-root user, so for local runs either point `audit.path` somewhere
writable, use `stdout`, or set `audit.enabled: false`.

**In a mesh deployment, prefer `audit.path: stdout`.** The audit trail is
the only record of the mesh-verified `principal`, and a file on local disk
dies with the allocation. Streaming to stdout hands shipping to the
platform's log pipeline (Nomad alloc logs, kubelet, vector/promtail/
fluent-bit) with no sidecar tailer and no rotation to manage; application
logs go to stderr, so the streams stay separable.

## Storage Backend

Garmr reads policies from disk. Setting `policy_dir` alone selects the
filesystem backend rooted there; `storage` configures it explicitly:

```yaml
storage:
  type: "filesystem"
  root: "/etc/garmr/policies"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `storage.type` | _(empty)_ | Backend type. `filesystem` is the only implemented backend. When set, `policy_dir` is ignored. |
| `storage.root` | `/policies` | Root directory. Applies only when `storage.type` is set — it does **not** fall back to `policy_dir`. |

A misconfigured storage backend (unknown type, missing root directory, a
policy set that fails to load) is fatal at startup: the server refuses to
start rather than silently running without policies. Configuring no source
at all is not an error; see [Policy Configuration](#policy-configuration).

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

On Consul, Envoy only injects XFCC when the service's protocol is `http`.
Without a `service-defaults` entry setting `Protocol = "http"` the header
never arrives, every caller shares the sidecar's bucket, and the audit log has
no principal (see `deploy/nomad/garmr-service-defaults.hcl`).

Other behavior worth knowing:

- An unrecognized `client_identifier` is fatal at startup rather than
  silently falling back to `ip`.
- Probe endpoints (`/health`, `/ready`, `/healthz`, `/readyz`, `/livez`) and
  `/metrics` are never rate limited: a `429` on a probe reads as an unhealthy
  instance and gets it pulled from the mesh.
- Rejected requests get `429` and increment
  `garmr_rate_limit_hits_total`.

## Development Mode

Development mode switches the application logger to zap's development
configuration (human-readable, colored levels). It changes nothing else — no
security setting is relaxed — but its output is meant for terminals, not log
pipelines.

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
# max_validate_size: 1048576
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
#   header_name: "X-Client-ID"
#   client_rps: 1000
#   client_burst: 100
#   max_clients: 10000
#   trusted_proxies: []

# Logging configuration
log:
  level: "info"
  format: "json"

# Evaluation posture and budget
evaluation:
  require_match: true
  timeout: "10s"

# Audit logging ("stdout" / "stderr" stream records instead of a file)
audit:
  enabled: true
  path: "/var/log/garmr/audit.log"
  # max_size: 100      # MB before rotation
  # max_backups: 10
  # max_age: 30        # days

# Storage backend configuration (when set, policy_dir is ignored)
# storage:
#   type: "filesystem"
#   root: "/etc/garmr/policies"

# Development mode (optional)
# dev: true
```

## Command-Line Flags

Every `garmr-server` flag maps to a configuration key, and a flag that is
passed overrides both the environment variable and the config file.

| Flag | Config key | Default |
|------|------------|---------|
| `--config` | — | _(search path above)_ |
| `--http-addr` | `http_addr` | `:8080` |
| `--policy-dir` | `policy_dir` | _(none)_ |
| `--storage-type` | `storage.type` | _(empty)_ |
| `--storage-root` | `storage.root` | _(empty → `/policies`)_ |
| `--log-level` | `log.level` | `info` |
| `--log-format` | `log.format` | `json` |
| `--dev` | `dev` | `false` |
| `--shutdown-timeout` | `shutdown_timeout` | `30s` |
| `--max-recv-size` | `max_recv_size` | `16777216` |
| `--max-validate-size` | `max_validate_size` | `1048576` |
| `--read-timeout` | `read_timeout` | `30s` |
| `--write-timeout` | `write_timeout` | `60s` |
| `--idle-timeout` | `idle_timeout` | `120s` |
| `--evaluation-timeout` | `evaluation.timeout` | `10s` |
| `--require-match` | `evaluation.require_match` | `true` |
| `--audit` | `audit.enabled` | `true` |
| `--audit-path` | `audit.path` | `/var/log/garmr/audit.log` |
| `--audit-max-size` | `audit.max_size` | `100` (MB) |
| `--audit-max-backups` | `audit.max_backups` | `10` |
| `--audit-max-age` | `audit.max_age` | `30` (days) |
| `--api-key` | `auth.api_key` | _(empty)_ |
| `--api-key-header` | `auth.api_key_header` | `X-API-Key` |
| `--identity-header` | `auth.identity_header` | `X-Forwarded-Client-Cert` |
| `--cors-origins` | `cors.allowed_origins` | _(empty)_ |
| `--rate-limit` | `rate_limit.enabled` | `false` |
| `--rate-limit-rps` | `rate_limit.rps` | `100` |
| `--rate-limit-burst` | `rate_limit.burst` | `200` |
| `--rate-limit-per-client` | `rate_limit.per_client` | `true` |
| `--rate-limit-identifier` | `rate_limit.client_identifier` | `ip` |
| `--rate-limit-header` | `rate_limit.header_name` | `X-Client-ID` |
| `--rate-limit-client-rps` | `rate_limit.client_rps` | `1000` |
| `--rate-limit-client-burst` | `rate_limit.client_burst` | `100` |
| `--rate-limit-max-clients` | `rate_limit.max_clients` | `10000` |
| `--rate-limit-trusted-proxies` | `rate_limit.trusted_proxies` | _(none)_ |

Boolean flags take `--flag=false` to turn off (`--audit=false`,
`--require-match=false`). List flags take comma-separated values
(`--cors-origins https://a.example,https://b.example`).

## Tracing

OpenTelemetry tracing is configured only through the standard OTel
environment variables, not the config file. It stays off unless
`OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set.
`OTEL_EXPORTER_OTLP_PROTOCOL` selects `grpc` (default) or `http/protobuf`, and
`OTEL_SERVICE_NAME` overrides the default service name `garmr-server`. The
trace ID of each request is recorded in its audit record as `trace_id`.
