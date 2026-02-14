# Plugin Architecture

## Overview

Garmr uses a plugin architecture to keep the core binary lean while allowing extensibility. Only the filesystem storage backend is built-in; all other backends are loaded as plugins.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Garmr                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                        Plugin Manager                            │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │   │
│  │  │  Registry   │ │  Loader     │ │  Security   │               │   │
│  │  │  (types)    │ │  (so/dylib) │ │  (checksums)│               │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│         ┌────────────────────┼────────────────────┐                    │
│         │                    │                    │                    │
│  ┌──────▼──────┐     ┌───────▼───────┐    ┌──────▼──────┐             │
│  │  Built-in   │     │   External    │    │   Future    │             │
│  │  Plugins    │     │   Plugins     │    │   (WASM)    │             │
│  ├─────────────┤     ├───────────────┤    ├─────────────┤             │
│  │ filesystem  │     │ s3.so         │    │ custom.wasm │             │
│  │ (always)    │     │ consul.so     │    │ (sandboxed) │             │
│  │             │     │ duckdb.so     │    │             │             │
│  └─────────────┘     │ gcs.so        │    └─────────────┘             │
│                      │ azure.so      │                                 │
│                      └───────────────┘                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Plugin Types

| Type | Purpose | Examples |
|------|---------|----------|
| `storage` | Policy file backends | filesystem, s3, consul, duckdb |
| `auth` | Authentication providers | oidc, ldap, mtls |
| `notifier` | Event notifications | slack, pagerduty, webhook |
| `function` | Custom CUE functions | custom validators |

## Security Model

### Cryptographic Signing with Ed25519

Garmr uses Ed25519 signatures to verify plugin authenticity and integrity:

1. **Plugin author signs** plugin with their Ed25519 private key
2. **Garmr administrator adds** author's public key to trusted keys
3. **At load time**, Garmr verifies both checksum and signature
4. **Plugin only loads** if signature is valid AND key is trusted

```
┌─────────────────┐          ┌─────────────────┐
│  Plugin Author  │          │ Garmr Install.  │
├─────────────────┤          ├─────────────────┤
│                 │          │                 │
│  1. Build       │          │  4. Add pubkey  │
│     plugin.so   │          │     to trusted  │
│                 │          │     keys        │
│  2. Sign with   │          │                 │
│     private key │          │  5. Load plugin │
│                 │          │     → verify    │
│  3. Distribute: │  ───────►│     signature   │
│     plugin.so   │          │     → check     │
│     plugin.so.sig          │     trusted key │
│     plugin.so.sum          │                 │
│                 │          │  6. ✓ Load OK   │
└─────────────────┘          └─────────────────┘
```

### Why Ed25519?

| Aspect | Ed25519 | PGP/GPG |
|--------|---------|---------|
| Key size | 32 bytes public | 256+ bytes |
| Signature size | 64 bytes | 512+ bytes |
| Verification speed | ~50x faster than RSA | Slower |
| Complexity | Simple API | Web of trust, subkeys, expiry |
| Dependencies | stdlib only | External GPG binary |
| Key management | Single key format | Multiple formats, keyrings |

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

**Generate a signing key:**
```bash
garmr plugin key generate production-signing-key

# Output:
#   production-signing-key.key  (PRIVATE - keep secret!)
#   production-signing-key.pub  (PUBLIC - distribute)
```

**Sign a plugin:**
```bash
garmr plugin sign s3.so --key production-signing-key.key

# Creates:
#   s3.so.sig  (signature)
#   s3.so.sum  (checksum)
```

**Verify a plugin:**
```bash
garmr plugin verify s3.so --trusted-keys /etc/garmr/trusted-keys
```

### Trusted Keys File

```bash
# /etc/garmr/trusted-keys
# Garmr Plugin Trusted Keys
# Format: <base64-public-key> <comment>

MCowBQYDK2VwAyEAxxxxxxxx Production Signing Key
MCowBQYDK2VwAyEAyyyyyyyy Development Signing Key (expires 2025-01-01)
```

### Configuration

```cue
plugins: {
    security: {
        signing: {
            // Require signatures (reject unsigned plugins)
            required: true
            
            // Load trusted public keys from file
            trustedKeysFile: "/etc/garmr/trusted-keys"
            
            // Or embed keys directly in config
            trustedKeys: [{
                publicKey: "MCowBQYDK2VwAyEAxxxxxxxx"
                comment:   "Production Signing Key"
            }]
            
            // Reject plugins signed with unknown keys
            rejectUntrustedKeys: true
        }
    }
}
```

### Security Levels

| Level | Configuration | Use Case |
|-------|--------------|----------|
| **Maximum** | `allowExternal: false` | Air-gapped, compliance-critical |
| **High** | `signing.required: true` + trusted keys | Production |
| **Medium** | `signing.rejectUntrustedKeys: true` | Staging |
| **Development** | Default (allow unsigned) | Local development |

### CI/CD Integration

**GitHub Actions example:**
```yaml
- name: Sign plugin
  run: |
    echo "${{ secrets.PLUGIN_SIGNING_KEY }}" > signing.key
    garmr plugin sign s3.so --key signing.key --comment "v${{ github.ref_name }}"
    rm signing.key

- name: Upload artifacts
  uses: actions/upload-artifact@v3
  with:
    name: plugins
    path: |
      s3.so
      s3.so.sig
      s3.so.sum
```

**Verify in deployment:**
```bash
# Download artifacts
# Verify signatures before deployment
garmr plugin verify *.so --trusted-keys /etc/garmr/trusted-keys --strict

# Only deploy if verification passes
if [ $? -eq 0 ]; then
    cp *.so /opt/garmr/plugins/
fi
```

## Built-in Plugins

### Filesystem (Always Available)

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

**Capabilities:**
- Native file watching (inotify)
- SHA256 checksums
- Symbolic link support (optional)

## External Plugins

### S3 / MinIO

```cue
plugins: {
    plugins: {
        s3: {
            enabled: true
            type: "storage"
            config: {
                endpoint: "minio.storage.svc:9000"
                bucket: "garmr-policies"
                region: "us-east-1"
                useSsl: false
                pollInterval: "5s"
            }
        }
    }
}
```

**Build:**
```bash
go build -buildmode=plugin -o s3.so ./plugins/s3
```

### Consul

```cue
plugins: {
    plugins: {
        consul: {
            enabled: true
            type: "storage"
            config: {
                address: "consul.service.consul:8500"
                prefix: "garmr/policies/production"
                watch: true  // Uses blocking queries
            }
        }
    }
}
```

**Build:**
```bash
go build -buildmode=plugin -o consul.so ./plugins/consul
```

### DuckDB

```cue
plugins: {
    plugins: {
        duckdb: {
            enabled: true
            type: "storage"
            config: {
                database: "/var/lib/garmr/policies.duckdb"
                tableName: "policies"
                readOnly: true
            }
        }
    }
}
```

**Build:**
```bash
CGO_ENABLED=1 go build -buildmode=plugin -o duckdb.so ./plugins/duckdb
```

**Use Cases:**
- Policy caching with SQL queryability
- Analytics on policy evaluation
- Embedded database (no external dependencies)

## Plugin Development

### Interface

All plugins must implement:

```go
type Plugin interface {
    // Metadata returns plugin information
    Metadata() Metadata
    
    // Init initializes with configuration
    Init(ctx context.Context, config map[string]interface{}) error
    
    // Health checks plugin status
    Health(ctx context.Context) error
    
    // Close releases resources
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

### Example Plugin Structure

```go
// plugins/myplugin/main.go
package main

import (
    "context"
    "github.com/yourorg/garmr/internal/plugin"
    "github.com/yourorg/garmr/internal/storage"
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
    // Initialize backend
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

# Plugin requiring CGO (like DuckDB)
CGO_ENABLED=1 go build -buildmode=plugin -o myplugin.so ./plugins/myplugin
```

### Generating Checksums

```bash
# Generate checksum for plugin
sha256sum s3.so | awk '{print $1}'

# Or using Garmr CLI
garmr plugin checksum s3.so
```

## Deployment Patterns

### Pattern 1: Lean Deployment (Filesystem Only)

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

### Pattern 3: Consul for Service Mesh

```cue
plugins: {
    plugins: {
        consul: {
            enabled: true
            config: {
                address: "localhost:8500"  // Consul agent sidecar
                prefix: "garmr/policies"
                watch: true
            }
        }
    }
}
```

### Pattern 4: Multi-Backend with Fallback

```cue
policies: {
    storagePlugin: "s3"
    fallbackPlugins: ["consul", "filesystem"]
}
```

Priority order:
1. Try S3 first
2. Fall back to Consul if S3 fails
3. Fall back to filesystem if Consul fails

## CLI Commands

```bash
# Key management
garmr plugin key generate my-signing-key     # Generate Ed25519 key pair
garmr plugin key show my-signing-key.pub     # Display key info

# Signing
garmr plugin sign s3.so --key signing.key    # Sign a plugin
garmr plugin sign s3.so --key signing.key --comment "v1.2.0"

# Verification
garmr plugin verify s3.so --trusted-keys /etc/garmr/trusted-keys
garmr plugin verify s3.so --public-key "MCowBQYDK2Vw..."
garmr plugin verify *.so --trusted-keys /etc/garmr/trusted-keys --strict

# Runtime info (requires running Garmr)
garmr plugin list                            # List loaded plugins
garmr plugin info s3                         # Show plugin details
garmr plugin health                          # Health check all plugins
```

## Comparison with Feature Flags

| Aspect | Plugins | Feature Flags |
|--------|---------|---------------|
| Binary size | Smaller (load only what you need) | Larger (all code compiled in) |
| Attack surface | Smaller | Larger |
| Runtime flexibility | Load at startup | Toggle at runtime |
| Third-party extensions | Yes (.so files) | No (must fork) |
| Auditability | Clear (which .so loaded) | Less clear |
| Complexity | Higher | Lower |

**Plugins are better when:**
- Security is paramount
- Binary size matters
- Third-party extensions needed
- Clear audit trail required

**Feature flags are better when:**
- Runtime toggling needed
- Simpler deployment preferred
- All features trusted equally

## Future: WASM Plugins

For enhanced security, we plan to support WebAssembly plugins:

```cue
plugins: {
    plugins: {
        custom: {
            type: "function"
            runtime: "wasm"  // Sandboxed execution
            path: "/plugins/custom.wasm"
            config: {...}
        }
    }
}
```

Benefits:
- Sandboxed execution
- Language-agnostic (Rust, Go, C, etc.)
- Portable across architectures
- Memory-safe by default
