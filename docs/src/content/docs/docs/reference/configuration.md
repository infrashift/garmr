---
title: "Server Configuration"
description: "Configuration reference for the Garmr server"
sidebar:
  order: 2
  label: "Configuration"
---

Garmr is configured via a YAML configuration file. Copy the example configuration to `config.yaml` and customize it for your environment.

## Server Address

The server exposes a REST API on port 8080 by default.

```yaml
http_addr: ":8080"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `http_addr` | `:8080` | Address for the HTTP/REST server |

## Policy Configuration

Specify the directory where Garmr loads policy files (CUE format). An optional data directory can provide external data files for policy evaluation.

```yaml
policy_dir: "/etc/garmr/policies"
# data_dir: "/etc/garmr/data"  # Optional: external data files
```

| Setting | Default | Description |
|---------|---------|-------------|
| `policy_dir` | `/etc/garmr/policies` | Root directory for CUE policy files |
| `data_dir` | _(none)_ | Optional directory for external data files |

## TLS Configuration

Enable TLS to encrypt traffic between clients and the Garmr server. For mutual TLS (mTLS), provide a CA certificate and set the client authentication mode.

```yaml
tls:
  enabled: false
  cert: "/etc/garmr/tls/server.crt"
  key: "/etc/garmr/tls/server.key"
  # For mTLS (optional)
  # ca: "/etc/garmr/tls/ca.crt"
  # client_auth: "require"  # none, request, require
```

| Setting | Default | Description |
|---------|---------|-------------|
| `tls.enabled` | `false` | Enable TLS encryption |
| `tls.cert` | _(none)_ | Path to TLS certificate file |
| `tls.key` | _(none)_ | Path to TLS private key file |
| `tls.ca` | _(none)_ | Path to CA certificate for mTLS |
| `tls.client_auth` | `none` | Client auth mode: `none`, `request`, or `require` |

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

By default, Garmr uses the filesystem backend powered by the `policy_dir` setting. For shared or cloud-native deployments, you can configure S3 or MinIO as the storage backend.

### Filesystem (Default)

```yaml
storage:
  type: "filesystem"
  root: "/etc/garmr/policies"
```

### S3 / MinIO

```yaml
storage:
  type: "s3"           # or "minio"
  root: "policies/"    # S3 key prefix
  s3:
    endpoint: "minio.example.com:9000"  # omit for AWS S3
    bucket: "garmr-policies"
    region: "us-east-1"
    access_key: ""
    secret_key: ""
    use_ssl: true
    poll_interval: "10s"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `storage.type` | `filesystem` | Backend type: `filesystem`, `s3`, or `minio` |
| `storage.root` | _(from policy_dir)_ | Root path or S3 key prefix |
| `storage.s3.endpoint` | _(none)_ | S3-compatible endpoint (omit for AWS) |
| `storage.s3.bucket` | _(none)_ | S3 bucket name |
| `storage.s3.region` | _(none)_ | AWS region |
| `storage.s3.access_key` | _(none)_ | Access key (use IAM roles in production) |
| `storage.s3.secret_key` | _(none)_ | Secret key (use IAM roles in production) |
| `storage.s3.use_ssl` | `true` | Use SSL for S3 connections |
| `storage.s3.poll_interval` | `10s` | How often to poll for policy changes |

For more details on storage backends, see the [Storage Backends](/garmr/docs/advanced/storage-backends/) documentation.

## Plugins

Garmr supports loading external plugins from a directory. Plugins extend functionality with additional storage backends, authentication providers, and more.

```yaml
# plugin_dir: "/etc/garmr/plugins"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `plugin_dir` | _(none)_ | Directory containing plugin `.so` files |

For more details on the plugin system, see the [Plugin Architecture](/garmr/docs/advanced/plugins/) documentation.

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
# data_dir: "/etc/garmr/data"

# TLS configuration (optional)
tls:
  enabled: false
  cert: "/etc/garmr/tls/server.crt"
  key: "/etc/garmr/tls/server.key"
  # ca: "/etc/garmr/tls/ca.crt"
  # client_auth: "require"

# Logging configuration
log:
  level: "info"
  format: "json"

# Audit logging
audit:
  enabled: true
  path: "/var/log/garmr/audit.log"

# Storage backend configuration
# storage:
#   type: "filesystem"
#   root: "/etc/garmr/policies"

# Plugin directory (optional)
# plugin_dir: "/etc/garmr/plugins"

# Development mode (optional)
# dev: true
```
