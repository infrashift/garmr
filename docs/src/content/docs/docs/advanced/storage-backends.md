---
title: "Policy Storage"
description: "How Garmr loads policies from disk, and how to serve them from object storage"
sidebar:
  order: 1
  label: "Policy Storage"
---

## Overview

Garmr reads policies through a small storage abstraction. The engine and the
loader never touch storage details directly — they go through the
`storage.Backend` interface.

**One backend is implemented: `filesystem`.** It is what `--policy-dir` uses,
and it is the path every deployment takes today. If you keep policies in
object storage, [sync them onto disk](#serving-policies-from-object-storage)
and point Garmr at the result.

## Configuration

The filesystem backend is selected automatically when you pass `--policy-dir`:

```bash
garmr-server --policy-dir /etc/garmr/policies
```

Equivalently, in `config.yaml`:

```yaml
storage:
  type: "filesystem"
  root: "/etc/garmr/policies"
```

| Setting | Env var | Default | Description |
|---------|---------|---------|-------------|
| `storage.type` | `GARMR_STORAGE_TYPE` | `filesystem` | Backend type |
| `storage.root` | `GARMR_STORAGE_ROOT` | — | Root directory |
| `policy_dir` | `GARMR_POLICY_DIR` | — | Shorthand: selects the filesystem backend rooted here |

By default the backend includes `**/*.cue` and excludes `**/*_test.cue` and
`**/testdata/**`, so `garmr test` fixtures sitting alongside policies are not
loaded as policies.

A backend that cannot be initialised, or a policy set that cannot be loaded,
**fails startup**. Running with zero policies is not a safe default: under
`require_match` (the default) it denies everything, and without it, allows
everything.

## The Backend interface

```go
type Backend interface {
    // Type returns the backend type identifier.
    Type() string

    // List returns all files matching the pattern.
    List(ctx context.Context, pattern string) ([]FileInfo, error)

    // Get retrieves file content.
    Get(ctx context.Context, path string) ([]byte, error)

    // GetReader returns a reader for streaming large files.
    GetReader(ctx context.Context, path string) (io.ReadCloser, error)

    // Stat returns file metadata without reading content.
    Stat(ctx context.Context, path string) (*FileInfo, error)

    // Checksum returns the checksum of a file (for change detection).
    Checksum(ctx context.Context, path string) (string, error)

    // Close releases any resources held by the backend.
    Close() error
}
```

Backends register themselves with the default registry:

```go
func init() {
    storage.Register("filesystem", NewFilesystemBackend)
}
```

`storage.New(cfg)` resolves `cfg.Type` against that registry.

### How the loader uses it

`LoadPoliciesFromBackend` special-cases the filesystem backend and loads the
directory directly. Any other backend has its files staged into a temporary
directory first and is then loaded from there, because CUE's loader resolves
imports and package structure against a real filesystem.

Staged paths are checked for containment before anything is written: a backend
key containing `..` or an absolute path aborts the load rather than writing
outside the staging directory.

## Path traversal protection

The filesystem backend confines every read to its root:

```go
// WithinRoot reports whether fullPath is root or inside it.
// A bare prefix check is not enough: "/policiesX" has "/policies" as a
// string prefix without being inside it.
func WithinRoot(root, fullPath string) bool {
    cleanRoot := filepath.Clean(root)
    cleaned := filepath.Clean(fullPath)
    return cleaned == cleanRoot || strings.HasPrefix(cleaned, cleanRoot+string(os.PathSeparator))
}
```

`Get`, `GetReader` and `Stat` all apply it and return `ErrAccessDenied` on a
traversal attempt.

## Reloading policies

Reload is **explicit**. There is no filesystem watcher and no poller:

```bash
curl -X POST http://localhost:8080/v1/policies/reload
```

The reload compiles a complete new policy set and swaps it in atomically, so
in-flight evaluations finish against the old set and never observe a partial
one. If the new set fails to compile, the old one stays live.

In Kubernetes you generally do not need to call it: the Helm chart stamps a
`checksum/config` annotation onto the Deployment, so changing the ConfigMap
rolls the pods.

:::note[Why there is no automatic watching]
An earlier version of this page described automatic change detection. It was
never wired up, and the obvious implementation would not have worked for the
deployment that matters: Kubernetes projects a ConfigMap by swapping a
`..data` symlink, `filepath.WalkDir` does not follow symlinks, and the
resulting events never match `**/*.cue`. It would have appeared to work in
local development and silently done nothing in production. See `TODO.md` for
what a correct implementation would need.
:::

## Serving policies from object storage

Garmr has no S3, GCS, or Azure backend. Sync objects onto the pod's filesystem
and point `--policy-dir` at the mount. This keeps credential handling, retries,
and rotation in tooling built for it, and it means Garmr's only input is a
directory.

### Init container

```yaml
spec:
  initContainers:
    - name: fetch-policies
      image: minio/mc:latest
      command:
        - sh
        - -c
        - |
          mc alias set src "$S3_ENDPOINT" "$S3_ACCESS_KEY" "$S3_SECRET_KEY"
          mc mirror --overwrite --remove src/garmr-policies /policies
      env:
        - name: S3_ENDPOINT
          value: https://s3.example.com
        - name: S3_ACCESS_KEY
          valueFrom:
            secretKeyRef: {name: garmr-policy-store, key: access-key}
        - name: S3_SECRET_KEY
          valueFrom:
            secretKeyRef: {name: garmr-policy-store, key: secret-key}
      volumeMounts:
        - name: policies
          mountPath: /policies
  containers:
    - name: garmr
      args: ["--policy-dir", "/policies"]
      volumeMounts:
        - name: policies
          mountPath: /policies
          readOnly: true
  volumes:
    - name: policies
      emptyDir: {}
```

Credentials live in a Secret rather than in Garmr's config, and on AWS the init
container can use IRSA and carry no static credentials at all.

To pick up changes, roll the Deployment — the init container re-syncs on every
pod start.

### Other options

| Approach | When it fits |
|----------|--------------|
| ConfigMap (Helm `policies.inline`) | Small policy sets managed with the release |
| Init container sync | Policies in object storage, updated on rollout |
| CSI volume (Secrets Store, s3-csi) | Policies in object storage, mounted directly |
| PVC | Policies written by another process in-cluster |
| Baked into the image | Immutable, versioned with the binary |

## GitOps workflow

Policies are files, so the usual review flow applies. Validate them in CI
before they reach a cluster:

```yaml
- name: Validate policies
  run: garmr validate ./policies
```

`garmr validate` runs locally with the same loader the server uses at
startup — no server process needed in CI.

`garmr policy lock` and `garmr policy validate-lock` record and verify content
hashes if you want to detect drift between what was reviewed and what is
deployed.

## Adding a backend

Implement `Backend`, register it in an `init()`, and the loader's staging path
handles the rest:

```go
func init() {
    storage.Register("mybackend", NewMyBackend)
}
```

Before adding one, check whether syncing to disk covers your case — it usually
does, and it keeps credentials out of Garmr.
