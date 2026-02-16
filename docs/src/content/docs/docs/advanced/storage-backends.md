---
title: "Storage Backends"
description: "Configure policy storage with filesystem, S3, or MinIO"
sidebar:
  order: 1
  label: "Storage Backends"
---

## Overview

Garmr uses a pluggable storage backend architecture. The engine and loader are completely decoupled from storage implementation details -- they only interact with the `storage.Backend` interface.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Garmr                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │    Engine    │────▶│    Loader    │────▶│   Backend    │    │
│  │              │     │              │     │  Interface   │    │
│  └──────────────┘     └──────────────┘     └──────┬───────┘    │
│                                                    │            │
└────────────────────────────────────────────────────┼────────────┘
                                                     │
                     ┌───────────────────────────────┼───────────────────────────────┐
                     │                               │                               │
              ┌──────▼──────┐               ┌───────▼───────┐               ┌───────▼───────┐
              │  Filesystem │               │  S3 / MinIO   │               │  GCS / Azure  │
              │   Backend   │               │    Backend    │               │    Backend    │
              └──────┬──────┘               └───────┬───────┘               └───────┬───────┘
                     │                               │                               │
              ┌──────▼──────┐               ┌───────▼───────┐               ┌───────▼───────┐
              │ Local Disk  │               │   S3 Bucket   │               │  Cloud Blob   │
              │ / NFS / PVC │               │   MinIO       │               │   Storage     │
              └─────────────┘               └───────────────┘               └───────────────┘
```

## Backend Interface

All storage backends implement this interface:

```go
type Backend interface {
    // Type returns the backend identifier
    Type() string

    // List returns all files matching pattern
    List(ctx context.Context, pattern string) ([]FileInfo, error)

    // Get retrieves file content
    Get(ctx context.Context, path string) ([]byte, error)

    // GetReader returns a streaming reader
    GetReader(ctx context.Context, path string) (io.ReadCloser, error)

    // Stat returns file metadata
    Stat(ctx context.Context, path string) (*FileInfo, error)

    // Watch returns change events (nil if unsupported)
    Watch(ctx context.Context, pattern string) (<-chan Event, error)

    // Checksum returns file checksum for change detection
    Checksum(ctx context.Context, path string) (string, error)

    // Close releases resources
    Close() error
}
```

## Supported Backends

| Backend | Watch Support | Change Detection | Use Case |
|---------|---------------|------------------|----------|
| `filesystem` | Native (inotify) | Checksum (SHA256) | Local dev, VMs, PVCs |
| `s3` / `minio` | Polling | ETag or SHA256 | Production, shared storage |
| `gcs` | Polling | Generation ID | GCP deployments |
| `azure` | Polling | ETag | Azure deployments |

## Configuration

### Filesystem (Default)

```cue
storage: {
    type: "filesystem"
    root: "/policies"
    options: {
        followSymlinks: false
    }
}
```

### MinIO (Self-Hosted S3)

```cue
storage: {
    type: "minio"
    root: "policies/"  // Prefix in bucket
    options: {
        endpoint:        "minio.storage.svc.cluster.local:9000"
        bucket:          "garmr-policies"
        accessKeyId:     "${MINIO_ACCESS_KEY}"
        secretAccessKey: "${MINIO_SECRET_KEY}"
        useSsl:          false
        pollInterval:    "5s"
    }
}
```

### AWS S3 with IAM Role

```cue
storage: {
    type: "s3"
    root: "production/policies/"
    options: {
        region: "us-west-2"
        bucket: "company-policies"
        // No credentials = use IAM role (recommended)
        pollInterval: "30s"
    }
}
```

## Architecture Benefits

### 1. Engine Remains Storage-Agnostic

```go
// Engine only sees PolicyFile, not storage details
type Engine struct {
    loader *loader.Loader  // Uses Backend interface internally
}

func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) {
    // Engine never knows if policy came from disk, S3, or anywhere else
    policy := e.loader.GetPolicy(ctx, namespace, name)
    // ... evaluate
}
```

### 2. Unified Change Detection

All backends provide consistent change detection:

```go
// Loader handles change detection uniformly
switch l.config.ReloadMode {
case ReloadWatch:
    // Uses backend.Watch() - native for filesystem, polling for S3
    events, _ := l.backend.Watch(ctx, "**/*.cue")
case ReloadPoll:
    // Compares checksums periodically
    checksum, _ := l.backend.Checksum(ctx, path)
}
```

### 3. Easy to Add New Backends

```go
// Register a new backend
func init() {
    storage.Register("mycloud", func(cfg storage.Config) (storage.Backend, error) {
        return NewMyCloudBackend(cfg)
    })
}
```

## Deployment Patterns

### Pattern 1: Simple Container Mount

```yaml
# docker-compose.yml
services:
  garmr:
    image: garmr:latest
    volumes:
      - ./policies:/policies:ro
    environment:
      GARMR_STORAGE_TYPE: filesystem
      GARMR_STORAGE_ROOT: /policies
```

### Pattern 2: Kubernetes with ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: garmr-policies
data:
  release-gate-prod.cue: |
    // Policy content...

---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: garmr
          volumeMounts:
            - name: policies
              mountPath: /policies
              readOnly: true
      volumes:
        - name: policies
          configMap:
            name: garmr-policies
```

### Pattern 3: MinIO Shared Storage

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ Garmr Pod (1)    │    │ Garmr Pod (2)    │    │ Garmr Pod (3)    │      │
│  │              │    │              │    │              │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             │                                   │
│                      ┌──────▼───────┐                           │
│                      │    MinIO     │                           │
│                      │   Service    │                           │
│                      └──────┬───────┘                           │
│                             │                                   │
│                      ┌──────▼───────┐                           │
│                      │garmr-policies│                           │
│                      │   bucket     │                           │
│                      └──────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Benefits:
- Single source of truth for all Garmr replicas
- No volume mounts needed per pod
- Easy to update policies (upload to bucket)
- Scales horizontally
```

### Pattern 4: GitOps with S3

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Git Repo  │────▶│   CI/CD     │────▶│   S3/MinIO  │◀────│Garmr Agent │
│  (policies) │     │  (sync)     │     │  (storage)  │     │ (consumer)  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                    │                   │                   │
      │ 1. Commit          │ 2. Upload         │ 3. Poll           │
      │    policy +        │    to bucket      │    for changes    │
      │    lock file       │                   │                   │
      ▼                    ▼                   ▼                   ▼
```

**CI/CD Script:**
```bash
#!/bin/bash
# sync-policies.sh

# Validate lock files
garmr policy validate-lock policies/**/*.cue

# Sync to MinIO
mc mirror --overwrite policies/ myminio/garmr-policies/

echo "Policies synced to MinIO"
```

## Change Detection Comparison

| Backend | Method | Latency | Overhead |
|---------|--------|---------|----------|
| Filesystem + Watch | inotify events | ~1ms | Very low |
| Filesystem + Poll | SHA256 comparison | pollInterval | Medium |
| S3/MinIO | ETag polling | pollInterval | Low (metadata only) |
| S3 + Event Bridge | SQS/SNS events | ~1-5s | Low |

## Security Considerations

### Path Traversal Protection

```go
func (b *FilesystemBackend) Get(ctx context.Context, path string) ([]byte, error) {
    fullPath := filepath.Join(b.root, path)

    // SECURITY: Prevent escaping root directory
    if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(b.root)) {
        return nil, &ErrAccessDenied{Path: path, Reason: "path traversal attempt"}
    }

    return os.ReadFile(fullPath)
}
```

### S3 Credential Handling

```cue
// RECOMMENDED: Use IAM roles (no credentials in config)
storage: {
    type: "s3"
    options: {
        region: "us-west-2"
        bucket: "policies"
        // No accessKeyId/secretAccessKey = use IAM
    }
}

// If credentials needed, use environment variables
storage: {
    type: "s3"
    options: {
        accessKeyId:     "${AWS_ACCESS_KEY_ID}"
        secretAccessKey: "${AWS_SECRET_ACCESS_KEY}"
    }
}
```

### Read-Only Access

- All backends treat storage as read-only
- Garmr never writes to storage (except lock files in special modes)
- Use bucket policies / IAM to enforce read-only access

## Performance Considerations

### S3 Polling Efficiency

```go
// List operation returns ETags, avoiding per-file Stat calls
infos, _ := backend.List(ctx, "**/*.cue")

for _, info := range infos {
    // ETag already in info.Checksum
    if info.Checksum != cachedChecksum {
        // Only then fetch content
        content, _ := backend.Get(ctx, info.Path)
    }
}
```

### Caching Strategy

1. **Policy Content**: Cached in Loader until checksum changes
2. **Evaluation Results**: Cached in Engine (separate cache)
3. **Checksums**: Cached per poll cycle

### Recommended Poll Intervals

| Scenario | Interval | Rationale |
|----------|----------|-----------|
| Development | 1-2s | Fast feedback |
| Production (low change rate) | 30-60s | Reduce API calls |
| Production (frequent updates) | 5-10s | Balance freshness vs load |
| GitOps with lock files | On-demand | Only check when evaluating |

## Migration Guide

### From Filesystem to MinIO

1. **Update configuration:**
```cue
// Before
storage: {
    type: "filesystem"
    root: "/policies"
}

// After
storage: {
    type: "minio"
    root: "policies/"
    options: {
        endpoint: "minio:9000"
        bucket:   "garmr-policies"
    }
}
```

2. **Sync existing policies:**
```bash
mc cp --recursive /policies/ myminio/garmr-policies/
```

3. **Deploy with new config** - no code changes needed

### Adding a New Backend

1. Implement `storage.Backend` interface
2. Register in `init()`:
```go
func init() {
    storage.Register("mybackend", NewMyBackend)
}
```
3. Add configuration schema to `schemas/storage.cue`
4. Document in this file

## Summary

| Aspect | Filesystem | S3/MinIO |
|--------|------------|----------|
| Setup complexity | Low | Medium |
| Scaling | Limited | Excellent |
| Change detection | Native watch | Polling |
| Shared across pods | Requires PVC | Native |
| GitOps integration | Direct mount | CI/CD sync |
| Cost | Free | Storage + API costs |

**Recommendation:**
- **Development / Single node**: Filesystem
- **Production / Multi-replica**: MinIO or S3
- **Strict version control**: Any backend + on-demand mode with lock files
