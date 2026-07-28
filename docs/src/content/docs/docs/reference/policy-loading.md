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
└── release/                        # Namespace: release
    ├── definitions.cue            # Shared definitions (same CUE package)
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

## Multi-file policies

A policy file may declare several policies as top-level fields, and a
namespace directory may hold many files. CUE's own package mechanism handles
sharing between them: put files in the same package and reference shared
definitions directly.

```
/policies/release/
├── definitions.cue     # shared _approvalGroups, _severityMap, ...
├── dev-release.cue
├── test-release.cue
└── prod-release.cue
```

All four files are loaded as one CUE package, so `dev-release.cue` can use a
definition declared in `definitions.cue` without any Garmr-specific manifest.

:::note[No `policyset.cue` manifest]
Earlier drafts of this page described a `kind: "PolicySet"` manifest with
`include` ordering, `evaluationOrder: "dependency"`, and per-policy `requires`
dependencies. None of it was implemented, and `requires` was separately
decided against (see `TODO.md`). The schema describing it has been removed.
Use CUE packages, as above.
:::

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
3. **GitOps** — use lock files as a repo-side review gate, and the policy-set
   digest to verify what a running server actually loaded.

## Lock File Workflow (GitOps)

Lock files are read by CI only — the server never reads them. Their job is
to fail the pipeline when a policy changed without being re-reviewed.

```bash
# 1. Update policy
vim policies/release/prod-release.cue

# 2. Generate lock file
garmr policy lock policies/release/prod-release.cue

# 3. Commit both
git add policies/release/prod-release.cue
git add policies/release/prod-release.cue.lock
git commit -m "Update production release policy"

# 4. CI gate: fail if any policy changed without a lock update
garmr policy validate-lock policies/

# 5. Deploy (CI/CD lands files on the server's policy volume, then either
#    restarts the instance or calls POST /v1/policies/reload)

# 6. Verify convergence: the server's digest must match the checkout's
garmr policy digest policies/
curl -s $GARMR/v1/policies | jq -r .digest
```
