---
title: "Policy Loading"
description: "Policy loading architecture and hot-reload strategies"
sidebar:
  order: 1
  label: "Policy Loading"
---

## Overview

Garmr is designed to be deployed in containerized environments where policies are mounted as read-only volumes. This document explains the policy loading architecture and configuration options.

## Directory Structure

```
/policies/                          # Root directory (configurable)
├── production/                     # Namespace: production
│   ├── release-gate.cue           # Policy: release-gate
│   ├── release-gate.cue.lock      # Lock file (optional)
│   └── security/
│       └── sbom-policy.cue        # Policy: sbom-policy
├── staging/                        # Namespace: staging
│   └── release-gate.cue
├── shared/                         # Namespace: shared
│   └── definitions.cue            # Shared definitions
└── release-pipeline/               # Policy Set
    ├── policyset.cue              # Manifest
    ├── definitions.cue
    ├── dev-release.cue
    ├── test-release.cue
    └── prod-release.cue
```

## Configuration (CUE)

Garmr uses CUE for its own configuration, ensuring type safety:

```cue
// /etc/garmr/config.cue
{
    apiVersion: "config.garmr.io/v1"

    server: {
        http: address: ":8080"
    }

    policies: {
        rootDir: "/policies"

        namespaceStrategy: {
            mode: "hybrid"      // Use directory, allow override
            directoryDepth: 0   // First subdir is namespace
        }

        reload: {
            enabled: true
            strategy: {
                mode: "watch"   // or "poll", "ondemand", "jit"
            }
        }
    }

    engine: {
        parallelRules: true
        cache: {
            enabled: true
            size: 10000
            ttl: "60s"
        }
    }
}
```

## Namespace Resolution

| Mode | Behavior |
|------|----------|
| `directory` | Namespace from directory structure at configured depth |
| `explicit` | Namespace must be in policy `metadata.namespace` |
| `hybrid` | Use metadata if present, else derive from directory |

### Examples

```
Path: /policies/production/release-gate.cue
Mode: directory, depth=0
Result: namespace=production, name=release-gate

Path: /policies/team-a/security/sbom.cue
Mode: directory, depth=0
Result: namespace=team-a, name=sbom

Path: /policies/team-a/security/sbom.cue
Mode: directory, depth=1
Result: namespace=security, name=sbom
```

## Hot Reload Strategies

### 1. Watch Mode (Default)

Uses file system notifications (inotify/fsnotify).

```cue
reload: strategy: mode: "watch"
```

**Pros:**
- Immediate detection (~ms latency)
- Low CPU usage

**Cons:**
- May not work across all mount types in containers
- inotify limits may be hit with many files

**Best for:** Development, VMs with local storage

### 2. Poll Mode

Periodically scans directory for changes.

```cue
reload: strategy: {
    mode: "poll"
    pollInterval: "5s"
}
```

**Pros:**
- Works with any mount type
- Simple, predictable

**Cons:**
- Higher latency (up to pollInterval)
- More I/O operations

**Best for:** Containers with mounted volumes, NFS

### 3. On-Demand Mode (Lock Files)

Checks lock file checksum before evaluation.

```cue
reload: strategy: {
    mode: "ondemand"
    lockFiles: {
        enabled: true
        extension: ".lock"
    }
}
```

**Lock file format:**
```json
{
    "checksum": "sha256:abc123...",
    "version": "2.5.0",
    "updatedAt": "2024-12-06T10:00:00Z",
    "updatedBy": "ci-pipeline"
}
```

**Flow:**
1. Request arrives for policy `release-gate`
2. Garmr reads `release-gate.cue.lock`
3. Compares lock checksum with cached policy checksum
4. If match -- use cached policy
5. If mismatch -- reload policy, update cache

**Pros:**
- Explicit version control
- Git-friendly (lock files can be committed)
- Works with any CI/CD pipeline

**Cons:**
- Requires lock file management
- Slight overhead per evaluation

**Best for:** GitOps workflows, strict version control

### 4. JIT Mode (Just-In-Time)

Loads policy from disk immediately before evaluation.

```cue
reload: strategy: {
    mode: "jit"
    jitCache: {
        enabled: true
        ttl: "5s"      // 0s = always read from disk
    }
}
```

**Flow:**
1. Request arrives for policy `release-gate`
2. Check JIT cache (if enabled and TTL > 0)
3. If cache miss or expired -- read from disk
4. Evaluate policy
5. Update JIT cache

**Pros:**
- Always gets latest policy
- Simple mental model
- Good for frequently changing policies

**Cons:**
- Higher I/O per evaluation
- Potential latency variance

**Best for:** Development, testing, policies that change frequently

## Recommendation by Deployment Type

| Deployment | Recommended Mode | Rationale |
|------------|-----------------|-----------|
| **Development** | `watch` | Immediate feedback |
| **Kubernetes (ConfigMap)** | `poll` (5s) | ConfigMaps don't trigger inotify reliably |
| **Kubernetes (PVC)** | `watch` | Works with persistent volumes |
| **Docker/Podman** | `poll` (5s) | Bind mounts may not trigger inotify |
| **GitOps/ArgoCD** | `ondemand` | Version control with lock files |
| **High-frequency updates** | `jit` (ttl=5s) | Balance freshness vs I/O |

## Policy Sets

For complex policies spanning multiple files:

```
/policies/release-pipeline/
├── policyset.cue          # Manifest
├── definitions.cue        # Shared definitions (#RulePriority, etc.)
├── input-schema.cue       # #ReleaseInput schema
├── dev-release.cue        # Dev environment policy
├── test-release.cue       # Test environment policy
├── acc-release.cue        # Acceptance environment policy
└── prod-release.cue       # Production environment policy
```

### Manifest (policyset.cue)

```cue
{
    apiVersion: "policy.garmr.io/v1"
    kind: "PolicySet"
    metadata: {
        name: "release-pipeline"
        namespace: "release"
        version: "2.0.0"
    }
    spec: {
        include: [
            "definitions.cue",
            "input-schema.cue",
            "dev-release.cue",
            "test-release.cue",
            "acc-release.cue",
            "prod-release.cue",
        ]

        // Shared definitions unified with each policy
        definitions: {
            _approvalGroups: {
                prod: ["release-managers"]
            }
        }

        evaluationOrder: "dependency"

        policies: [{
            file: "prod-release.cue"
            requires: ["acc-release.cue"]
        }]
    }
}
```

### Benefits

1. **Modularity** - Split large policies into focused files
2. **Reuse** - Share definitions across policies
3. **Versioning** - Version the entire set as a unit
4. **Dependencies** - Express evaluation order

### When NOT to Use Policy Sets

- Simple, single-file policies
- Policies that don't share definitions
- When you want maximum loading flexibility

## Container Deployment Example

### Dockerfile

```dockerfile
FROM gcr.io/distroless/static:nonroot

COPY garmr /usr/local/bin/garmr
COPY config.cue /etc/garmr/config.cue

# Policies are mounted at runtime
VOLUME /policies

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/garmr", "serve", "--config", "/etc/garmr/config.cue"]
```

### Podman/Docker Run

```bash
# Create read-only policy volume
podman run -d \
    --name garmr \
    -v ./policies:/policies:ro \
    -v ./config.cue:/etc/garmr/config.cue:ro \
    -p 8080:8080 \
    garmr:latest
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: garmr
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: garmr
          image: garmr:latest
          ports:
            - containerPort: 8080
              name: http
          volumeMounts:
            - name: policies
              mountPath: /policies
              readOnly: true
            - name: config
              mountPath: /etc/garmr
              readOnly: true
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
      volumes:
        - name: policies
          configMap:
            name: garmr-policies
        - name: config
          configMap:
            name: garmr-config
```

## Performance Considerations

### File I/O Impact

| Mode | I/O per Request | Latency Impact |
|------|-----------------|----------------|
| watch | 0 (cached) | None |
| poll | 0 (cached) | None |
| ondemand | 1 read (lock file) | ~0.1ms |
| jit (ttl=0) | 1 read (policy) | ~0.5-2ms |
| jit (ttl=5s) | 0.2 avg (20% miss) | ~0.1-0.4ms avg |

### Recommendations

1. **Production**: Use `watch` or `poll` mode - policies are cached
2. **High throughput**: Enable result caching in engine
3. **Large policies**: Use policy sets for modular loading
4. **GitOps**: Use `ondemand` with lock files for controlled rollouts

## Lock File Workflow (GitOps)

```bash
# 1. Update policy
vim policies/release/prod-release.cue

# 2. Generate lock file
garmr policy lock policies/release/prod-release.cue

# 3. Commit both
git add policies/release/prod-release.cue
git add policies/release/prod-release.cue.lock
git commit -m "Update production release policy"

# 4. Deploy (CI/CD copies to mounted volume)
# Garmr detects lock file change and reloads policy
```

## Conclusion

The recommended approach for most deployments:

1. **Development**: `watch` mode for immediate feedback
2. **Production containers**: `poll` mode (5-10s interval)
3. **GitOps workflows**: `ondemand` mode with lock files
4. **Complex policies**: Use policy sets for organization

All modes support the same policy format - switching is just a configuration change.
