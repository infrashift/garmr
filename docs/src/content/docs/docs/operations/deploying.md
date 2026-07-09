---
title: "Deploying Garmr"
description: "Deployment models, Helm chart, Consul service mesh, and configuration essentials"
sidebar:
  order: 1
---

Garmr is a stateless HTTP service. Replicas share policy state by polling a
common storage backend — you can run as many pods as you like behind a service
or a mesh. This page covers the deployment models you'll hit in practice.

## Minimum configuration

Whatever you deploy onto, Garmr needs:

1. **A storage backend.** Either a filesystem directory mounted into the pod,
   or S3/MinIO. See [Storage Backends](../advanced/storage-backends).
2. **An HTTP listen address.** Defaults to `:8080`.
3. **An audit-log path.** Defaults to `/var/log/garmr/audit.log`.

That's it — everything else (metrics, tracing, auth) is opt-in.

## Helm chart

The repository ships a Helm chart at `deploy/helm/garmr/`.

```bash
helm upgrade --install garmr deploy/helm/garmr \
  --namespace garmr --create-namespace \
  -f your-values.yaml
```

Minimum useful `values.yaml`:

```yaml
replicaCount: 2
image:
  repository: ghcr.io/infrashift/garmr
  tag: "0.1.0"

policies:
  inline:
    example.cue: |
      apiVersion: "policy.garmr.io/v1"
      kind: "Policy"
      metadata: { name: "example", namespace: "default" }
      spec:
        rules: [{
          id: "r1"
          description: "env must be prod"
          severity: "high"
          expr: { match: { path: "env", equals: "prod" } }
          message: "env must be prod"
        }]
        enforcement: { action: "deny" }
```

The chart defaults assume:

- **Read-only root filesystem** — the pod writes only to `/var/log/garmr`
  and `/tmp`, both mounted as `emptyDir`.
- **Non-root container** — `runAsUser: 1000`, all capabilities dropped.
- **PodDisruptionBudget at minAvailable=1** when `replicaCount > 1`.
- **Pod anti-affinity** to spread replicas across nodes.

## Running behind a service mesh

When Garmr runs behind an Envoy sidecar (Consul Connect, Istio, Linkerd
with mTLS), the mesh terminates client mTLS and forwards the verified
identity in `X-Forwarded-Client-Cert`. Garmr parses the SPIFFE `URI=` field
and stores it on every audit-log entry as `principal`, so your audit trail
records *which service* made the call — not just an IP.

- **API key authentication should stay off** (`config.auth.api_key: ""`).
  The mesh already authenticated the caller.
- **Authorization** is enforced by mesh intentions / AuthorizationPolicies —
  Garmr does not re-check who may call it.
- **Audit principal** lands automatically; no extra config required as long
  as the XFCC header reaches Garmr.

### Consul Connect

See `deploy/helm/garmr/examples/consul-connect/` for a working example. The
short version:

```bash
helm upgrade --install garmr deploy/helm/garmr \
  --namespace garmr --create-namespace \
  --set mesh.consulConnect.enabled=true
```

Then apply ServiceIntentions to gate callers:

```yaml
apiVersion: consul.hashicorp.com/v1alpha1
kind: ServiceIntentions
metadata:
  name: garmr
spec:
  destination:
    name: garmr
  sources:
    - { name: policy-gateway, action: allow }
    - { name: "*", action: deny }
```

## Observability

### Metrics

`/metrics` exposes Prometheus-format metrics for policy evaluations
(`garmr_policy_evaluations_total`), evaluation duration histograms,
violations, active evaluations, cache hits/misses, rate-limit hits, and
recovered panics, plus Go runtime metrics. The endpoint is exempt from API
key authentication so Prometheus scrapers work without a shared secret.

Expose it to a Consul-aware Prometheus by adding these pod annotations:

```yaml
podAnnotations:
  consul.hashicorp.com/prometheus-scrape-port: "8080"
  consul.hashicorp.com/prometheus-scrape-path: "/metrics"
```

### Tracing

Set `tracing.endpoint` in Helm values (or `OTEL_EXPORTER_OTLP_ENDPOINT` in
the environment) to enable OTLP trace export. Garmr wraps every HTTP handler
with `otelhttp` and honors incoming `traceparent` headers regardless of
whether an exporter is configured — the trace id still shows up in the
audit log as `trace_id` for correlation.

```yaml
tracing:
  endpoint: otel-collector.observability.svc.cluster.local:4317
  protocol: grpc
  serviceName: garmr-server
```

### Health probes

- `/healthz` and `/livez` — liveness (cheap, cached; both serve the same
  check). Return 200 while the process is live.
- `/readyz` — readiness. Returns 503 until policies are loaded and the
  storage backend is reachable.
- `/health/deep` — comprehensive check including the storage backend, for
  debugging and monitoring (not for probes).

The Helm chart wires these probes automatically.

## High availability

Garmr replicas are fully stateless. Each replica:

- Loads policies from the configured storage backend at startup.
- Re-reads the backend on `POST /v1/policies/reload` or on filesystem
  inotify events (filesystem backend) or on a poll interval (S3 backend).
- Serves evaluation requests from its in-memory cache.

This means:

- **Multiple replicas stay in sync** via the shared backend, not leader
  election. There is no cross-replica coordination to fail.
- **Expect a brief convergence window** when a policy changes in S3 — new
  replicas will read the update on their next poll interval. Filesystem
  backends are eventually consistent only if a shared RWX volume is used.
- **A lost backend does not take Garmr down.** Pods continue serving from
  cached state until they restart.

## Graceful shutdown

Garmr traps SIGTERM and shuts the HTTP server down within 5 seconds by
default. Kubernetes sends SIGTERM at pod deletion and waits for
`terminationGracePeriodSeconds` (default 30). The chart leaves the default
grace period in place, which is more than enough for typical evaluations.

## Backup & restore

- **Filesystem backend:** policies are whatever files are on disk. Back up
  the directory with your usual volume snapshot tooling.
- **S3 backend:** enable bucket versioning and a lifecycle policy. Garmr
  does not implement its own backup.

Audit logs rotate via lumberjack (`max_size`, `max_backups`, `max_age` in
`config.audit`). Ship them off the pod to a long-term store — the chart
mounts them on `emptyDir` so they do not survive a pod restart.
