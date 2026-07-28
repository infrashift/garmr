---
title: "Deploying Garmr"
description: "Deployment models, Helm chart, Consul service mesh, and configuration essentials"
sidebar:
  order: 1
---

Garmr is a stateless HTTP service. Every replica compiles the same policy
directory at startup, so you can run as many pods as you like behind a service
or a mesh. This page covers the deployment models you'll hit in practice.

## Minimum configuration

Whatever you deploy onto, Garmr needs:

1. **A policy directory** mounted into the pod — from a ConfigMap, a PVC, a
   CSI volume, or an init container that syncs from object storage. See
   [Policy Storage](../advanced/storage-backends).
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
violations, active evaluations, policies loaded, policy load errors,
policy reloads (`garmr_policy_reloads_total{result="success"|"failure"}` —
alert on failures: a failed reload keeps the previous policy set serving
and is otherwise only visible in logs and the reload response),
rate-limit hits, and recovered panics, plus Go runtime metrics.
`garmr_policies_loaded{namespace=...}` is a snapshot of the current set:
a namespace whose policies disappear on reload drops out of the series.
The endpoint is exempt from API key authentication so Prometheus scrapers
work without a shared secret.

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
- `/readyz` — readiness. Returns 503 until policies are loaded. Runs only
  cheap in-process checks: the storage backend is *not* contacted, so a
  kubelet polling this endpoint does not generate backend traffic.
- `/health/deep` — comprehensive check, adding the storage backend round
  trip (is the policy volume still mounted and readable?), for operators
  and monitoring, not for probes. Returns 503 when any check fails, and —
  unlike the probe endpoints — requires the API key when one is set,
  because every call performs storage I/O.

The Helm chart wires these probes automatically.

## High availability

Garmr replicas are fully stateless. Each replica:

- Loads policies from the configured storage backend at startup, and fails
  to start if that load fails.
- Re-reads the backend on `POST /v1/policies/reload`. There is no watcher and
  no poller: reload is explicit, or happens implicitly when the pod restarts.
- Serves evaluation requests from its in-memory compiled policy set.

This means:

- **Multiple replicas stay in sync** via the shared backend, not leader
  election. There is no cross-replica coordination to fail.
- **Expect a convergence window** when policies change: replicas pick up the
  new set when they are reloaded or rolled. The chart's `checksum/config`
  annotation rolls pods automatically when the ConfigMap changes, so the
  window is the rollout.
- **A lost backend does not take Garmr down.** Pods continue serving from
  their compiled policy set until they restart — but a restart with an
  unreachable backend fails startup rather than serving zero policies.

## Graceful shutdown

Garmr traps SIGTERM, immediately flips `/readyz` to 503 so no new traffic
routes to the instance, and drains in-flight requests for up to
`shutdown_timeout` (default **30 seconds**, `--shutdown-timeout`).
Kubernetes sends SIGTERM at pod deletion and waits for
`terminationGracePeriodSeconds` (default 30). Because the drain budget and
the default grace period are the same length, either lower
`--shutdown-timeout` or raise `terminationGracePeriodSeconds` so a drain
that uses its full budget is not cut short by SIGKILL.

## Backup & restore

Policies are whatever files are on disk, so they are backed up wherever they
come from: the Git repository that renders the ConfigMap, the object-storage
bucket an init container syncs from (enable versioning there), or your usual
volume snapshot tooling for a PVC. Garmr does not implement its own backup.

Audit logs rotate via lumberjack (`max_size`, `max_backups`, `max_age` in
`config.audit`). Ship them off the pod to a long-term store — the chart
mounts them on `emptyDir` so they do not survive a pod restart.
