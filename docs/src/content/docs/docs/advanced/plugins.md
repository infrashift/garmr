---
title: "Plugin Architecture"
description: "Extending Garmr with plugins for storage, observability, and integrations"
sidebar:
  order: 0
  label: "Plugins"
---

## Overview

Garmr uses a plugin architecture to keep the core binary lean while allowing extensibility. Only the filesystem storage backend is built-in; all other backends and integrations are loaded as Go shared library plugins.

```
┌──────────────────────────────────────────────────────────────────┐
│                           Garmr                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                     Plugin Manager                         │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │  │
│  │  │  Registry   │ │  Loader     │ │  Security   │         │  │
│  │  │  (types)    │ │  (so/dylib) │ │  (signing)  │         │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
│         ┌────────────────────┼────────────────────┐              │
│         │                    │                    │              │
│  ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐       │
│  │  Built-in   │     │  Storage    │     │  Notifier/  │       │
│  │             │     │  Plugins    │     │  Auth       │       │
│  ├─────────────┤                         ├─────────────┤       │
│  │ filesystem  │                         │ kafka       │       │
│  │ (always)    │                         │ prometheus  │       │
│  │             │                         │ otel        │       │
│  └─────────────┘                         └─────────────┘       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Plugin Types

| Type | Purpose | Plugins |
|------|---------|---------|
| `storage` | Policy file backends | filesystem (built-in) |
| `notifier` | Metrics, tracing, streaming audit | kafka, prometheus, otel |

## Available Plugins

### Storage Plugins

#### Filesystem (Built-in)

Always available. Watches the local filesystem for policy files.

```cue
plugins: {
    plugins: {
        filesystem: {
            enabled: true
            type: "storage"
            config: {
                root: "/policies"
                followSymlinks: false
            }
        }
    }
}
```

S3-compatible object storage is available via the built-in storage registry (not a `.so` plugin). Configure it with `--storage-type s3` and the corresponding `--storage-*` flags.

### Notifier Plugins

#### Kafka

Kafka audit sink for streaming policy decisions to Kafka topics.

```cue
plugins: {
    plugins: {
        kafka: {
            enabled: true
            type: "notifier"
            config: {
                brokers: ["kafka-1:9092", "kafka-2:9092"]
                topic: "garmr-audit-decisions"
                clientId: "garmr"
                compression: "snappy"      // none, gzip, snappy, lz4, zstd
                requiredAcks: "all"        // none, leader, all
                tls: {
                    enabled: true
                    certFile: "/etc/garmr/tls/client.crt"
                    keyFile: "/etc/garmr/tls/client.key"
                    caFile: "/etc/garmr/tls/ca.crt"
                }
                sasl: {
                    enabled: true
                    mechanism: "SCRAM-SHA-256"
                    username: "garmr"
                    // password: "..."
                }
                privacy: {
                    redactSecrets: true
                }
            }
        }
    }
}
```

#### Prometheus

Prometheus metrics endpoint for policy evaluation observability.

```cue
plugins: {
    plugins: {
        prometheus: {
            enabled: true
            type: "notifier"
            config: {
                address: ":9090"
                path: "/metrics"
                namespace: "garmr"
                subsystem: "policy"
                enableGoMetrics: false
                enableProcessMetrics: false
            }
        }
    }
}
```

**Exposed metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `evaluations_total` | Counter | Total evaluations by decision |
| `evaluation_duration_seconds` | Histogram | Evaluation latency |
| `active_evaluations` | Gauge | Currently running evaluations |
| `violations_total` | Counter | Total violations |
| `policies_loaded` | Gauge | Number of loaded policies |
| `cache_hits_total` | Counter | Cache hits |
| `cache_misses_total` | Counter | Cache misses |
| `rate_limit_hits_total` | Counter | Rate-limited requests |
| `load_errors_total` | Counter | Policy load errors |
| `plugin_health` | Gauge | Plugin health status |

#### OpenTelemetry

Distributed tracing with OTLP export.

```cue
plugins: {
    plugins: {
        otel: {
            enabled: true
            type: "notifier"
            config: {
                serviceName: "garmr"
                environment: "production"
                exporter: {
                    type: "otlp-grpc"      // otlp-grpc, otlp-http
                    endpoint: "otel-collector:4317"
                    insecure: false
                }
                sampling: {
                    type: "ratio"          // always, never, ratio, parentbased
                    ratio: 0.1
                }
            }
        }
    }
}
```

---

## Security Model

### Cryptographic Signing with Ed25519

Garmr uses Ed25519 signatures to verify plugin authenticity and integrity:

1. **Plugin author signs** plugin with their Ed25519 private key
2. **Garmr administrator adds** author's public key to trusted keys
3. **At load time**, Garmr verifies both checksum and signature
4. **Plugin only loads** if signature is valid AND key is trusted

### Why Ed25519?

| Aspect | Ed25519 | PGP/GPG |
|--------|---------|---------|
| Key size | 32 bytes public | 256+ bytes |
| Signature size | 64 bytes | 512+ bytes |
| Verification speed | ~50x faster than RSA | Slower |
| Complexity | Simple API | Web of trust, subkeys, expiry |
| Dependencies | stdlib only | External GPG binary |

### File Format

```
plugin.so        # Plugin binary
plugin.so.sig    # Ed25519 signature
plugin.so.sum    # SHA256 checksum (human-readable)
```

**Signature file format:**
```
-----BEGIN GARMR PLUGIN SIGNATURE-----
Version: 1
KeyID: a1b2c3d4e5f6g7h8
Algorithm: ed25519
Checksum: sha256:e3b0c44298fc1c149afbf4c8996fb924...
Timestamp: 2024-12-06T15:30:00Z
Comment: S3 Plugin v1.2.0

<base64-encoded-signature>
-----END GARMR PLUGIN SIGNATURE-----
```

### Key Management

```bash
# Generate a signing key
garmr plugin key generate production-signing-key

# Sign a plugin
garmr plugin sign s3.so --key production-signing-key.key

# Verify a plugin
garmr plugin verify s3.so --trusted-keys /etc/garmr/trusted-keys
```

### Security Levels

| Level | Configuration | Use Case |
|-------|--------------|----------|
| **Maximum** | `allowExternal: false` | Air-gapped, compliance-critical |
| **High** | `signing.required: true` + trusted keys | Production |
| **Medium** | `signing.rejectUntrustedKeys: true` | Staging |
| **Development** | Default (allow unsigned) | Local development |

### Configuration

```cue
plugins: {
    security: {
        signing: {
            required: true
            trustedKeysFile: "/etc/garmr/trusted-keys"
            rejectUntrustedKeys: true
        }
    }
}
```

---

## Plugin Development

### Interface

All plugins must implement:

```go
type Plugin interface {
    Metadata() Metadata
    Init(ctx context.Context, config map[string]interface{}) error
    Health(ctx context.Context) error
    Close() error
}
```

Storage plugins additionally implement:

```go
type StoragePlugin interface {
    Plugin
    Backend() storage.Backend
}
```

### Example Plugin

```go
package main

import (
    "context"
    "github.com/infrashift/garmr/internal/plugin"
    "github.com/infrashift/garmr/internal/storage"
)

type MyPlugin struct {
    backend storage.Backend
}

func (p *MyPlugin) Metadata() plugin.Metadata {
    return plugin.Metadata{
        Name:        "myplugin",
        Type:        plugin.TypeStorage,
        Version:     "1.0.0",
        Description: "My custom storage backend",
    }
}

func (p *MyPlugin) Init(ctx context.Context, config map[string]interface{}) error {
    return nil
}

func (p *MyPlugin) Health(ctx context.Context) error {
    return nil
}

func (p *MyPlugin) Close() error {
    return nil
}

func (p *MyPlugin) Backend() storage.Backend {
    return p.backend
}

// REQUIRED: Export this symbol
var GarmrPlugin plugin.Plugin = &MyPlugin{}
```

### Building

```bash
# Standard plugin
go build -buildmode=plugin -o myplugin.so ./plugins/myplugin

# Plugin requiring CGO
CGO_ENABLED=1 go build -buildmode=plugin -o myplugin.so ./plugins/myplugin
```

---

## Deployment Patterns

### Pattern 1: Lean (Filesystem Only)

```dockerfile
FROM gcr.io/distroless/static:nonroot
COPY garmr /usr/local/bin/garmr
# No plugins directory - uses built-in filesystem only
```

```cue
plugins: {
    security: {
        allowExternal: false
    }
    plugins: {
        filesystem: {
            enabled: true
            config: root: "/policies"
        }
    }
}
```

### Pattern 2: Production with MinIO

```dockerfile
FROM gcr.io/distroless/static:nonroot
COPY garmr /usr/local/bin/garmr
COPY plugins/s3.so /opt/garmr/plugins/s3.so
```

```cue
plugins: {
    pluginDir: "/opt/garmr/plugins"
    security: {
        restrictToAllowed: true
        allowed: ["filesystem", "s3"]
        verifyChecksums: true
        checksums: {
            s3: "sha256:abc123..."
        }
    }
    plugins: {
        filesystem: {
            enabled: true
            config: root: "/local-cache"
        }
        s3: {
            enabled: true
            config: {
                endpoint: "minio:9000"
                bucket: "policies"
            }
        }
    }
}
```

### Pattern 3: Full Observability Stack

```cue
plugins: {
    pluginDir: "/opt/garmr/plugins"
    plugins: {
        "audit-file": {
            enabled: true
            config: {
                path: "/var/log/garmr/audit.log"
                format: "json"
            }
        }
        prometheus: {
            enabled: true
            config: {
                address: ":9090"
                path: "/metrics"
            }
        }
        otel: {
            enabled: true
            config: {
                exporter: {
                    type: "otlp-grpc"
                    endpoint: "otel-collector:4317"
                }
            }
        }
    }
}
```

## CLI Commands

```bash
# Key management
garmr plugin key generate my-signing-key     # Generate Ed25519 key pair
garmr plugin key show my-signing-key.pub     # Display key info

# Signing
garmr plugin sign s3.so --key signing.key    # Sign a plugin

# Verification
garmr plugin verify s3.so --trusted-keys /etc/garmr/trusted-keys
garmr plugin verify *.so --trusted-keys /etc/garmr/trusted-keys --strict

# Runtime info (requires running Garmr)
garmr plugin list                            # List loaded plugins
garmr plugin info s3                         # Show plugin details
garmr plugin health                          # Health check all plugins
```
