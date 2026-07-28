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

## Policy Configuration

Specify the directory where Garmr loads policy files (CUE format).

```yaml
policy_dir: "/etc/garmr/policies"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `policy_dir` | _(none)_ | Root directory for CUE policy files |

## TLS Configuration

Enable TLS to encrypt traffic between clients and the Garmr server. Mutual TLS (client certificate authentication) is not currently implemented.

```yaml
tls:
  enabled: false
  cert: "/etc/garmr/tls/server.crt"
  key: "/etc/garmr/tls/server.key"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `tls.enabled` | `false` | Enable TLS encryption |
| `tls.cert` | _(none)_ | Path to TLS certificate file |
| `tls.key` | _(none)_ | Path to TLS private key file |

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
| `audit.path` | `/var/log/garmr/audit.log` | File path for the audit log |

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

# TLS configuration (optional)
tls:
  enabled: false
  cert: "/etc/garmr/tls/server.crt"
  key: "/etc/garmr/tls/server.key"

# Authentication (optional)
# auth:
#   api_key: "change-me"
#   api_key_header: "X-API-Key"

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

# Storage backend configuration
# storage:
#   type: "filesystem"
#   root: "/etc/garmr/policies"

# Development mode (optional)
# dev: true
```
