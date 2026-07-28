---
title: "Policy Loading"
description: "How Garmr discovers, loads, and reloads policies"
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

## Reloading Policies

Reload is **explicit**. Garmr does not watch the filesystem and does not poll.

```bash
curl -X POST http://localhost:8080/v1/policies/reload
```

The reload compiles a complete new policy set in fresh CUE contexts and swaps
it in atomically: in-flight evaluations finish against the old set, and if the
new set fails to compile the old one stays live. A reload never leaves the
server serving a partially-loaded policy set.

### In Kubernetes

You usually do not need to call the endpoint. The Helm chart stamps a
`checksum/config` annotation onto the Deployment, so editing the ConfigMap
rolls the pods, and each new pod loads the new policies at startup.

For policies synced from object storage, an init container re-syncs on every
pod start — so a rollout is also the reload mechanism. See
[Policy Storage](/garmr/docs/advanced/storage-backends/).

### Startup behaviour

A policy set that cannot be loaded **fails startup**, and a server with zero
policies loaded reports `503` on `/readyz` and `/ready`. Running with no
policies is not a safe default: under `require_match` (the default) it denies
everything, and without it, allows everything.

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

Policies are compiled once at load time and held in memory, so evaluation does
no file I/O. Reload cost scales with the size of the policy set, not with
request volume.

The engine keeps a pool of compiled policy replicas (one per CPU, capped at 8)
so evaluations run concurrently without sharing a CUE context. Each replica
holds a full copy of the compiled policy set, which trades memory for
concurrency.

### Recommendations

1. **Large policy sets** — use policy sets for modular organisation.
2. **Reload frequency** — reload on deploy, not on a timer; each reload
   recompiles every policy into every replica.
3. **GitOps** — use lock files to detect drift between what was reviewed and
   what is deployed.

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
