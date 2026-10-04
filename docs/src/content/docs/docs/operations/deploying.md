---
title: "Deploying Garmr"
description: "Deployment models: Nomad with Consul Connect, the Helm chart, service-mesh identity, and fleet-wide policy reload"
sidebar:
  order: 1
---

Garmr is a stateless HTTP service. Every instance compiles the same policy
directory at startup, so you can run as many as you like behind a service
or a mesh. This page covers the two deployment targets the repository ships —
**Nomad with Consul Connect** (`deploy/nomad/`) and **Kubernetes via Helm**
(`deploy/helm/garmr/`) — and what they have in common.

## Minimum configuration

Whatever you deploy onto, Garmr needs:

1. **A policy directory** mounted into the instance — a Nomad host or CSI
   volume, a ConfigMap, a PVC, or an init container that syncs from object
   storage. See [Policy Storage](/garmr/docs/advanced/storage-backends/).
2. **An HTTP listen address.** Defaults to `:8080`.
3. **A writable audit destination.** Defaults to the file
   `/var/log/garmr/audit.log`, and the server refuses to start if it can't
   create that directory. In a mesh, prefer `--audit-path stdout` (see
   [Backup & restore](#backup--restore)).

That's it — everything else (metrics, tracing, auth) is opt-in.

## Nomad with Consul Connect

The production target. `deploy/nomad/` holds:

| File | Purpose |
|------|---------|
| `garmr-service-defaults.hcl` | Consul config entry declaring `Protocol = "http"`. **Apply first.** |
| `garmr-service.nomad.hcl` | Long-lived service instances (`count = 2`) behind Connect sidecars |
| `garmr-reload.nomad.hcl` | Parameterized batch job that reloads every instance from inside the mesh and verifies the digest |
| `garmr-batch.nomad.hcl` | Parameterized batch job for one-shot, just-in-time evaluation |

```bash
consul config write deploy/nomad/garmr-service-defaults.hcl
nomad job run deploy/nomad/garmr-service.nomad.hcl
nomad job run deploy/nomad/garmr-reload.nomad.hcl   # register the reload job
```

What the specs set, and why:

- **`Protocol = "http"` in service-defaults.** Consul proxies a service at L4
  unless it declares an application protocol, and Envoy only injects
  `X-Forwarded-Client-Cert` from an HTTP connection manager. Without it the
  header never arrives: every audit record has `"principal": ""` and
  identity-keyed rate limiting collapses into one shared bucket. Neither
  failure is loud.
- **Policies on a shared, read-only volume** (host volume `garmr-policies`,
  mounted at `/etc/garmr/policies`). CI/CD syncs the reviewed git checkout
  onto it; nothing edits it in place.
- **`--audit-path stdout`**, so Nomad's alloc log capture ships audit records
  and application logs stay on stderr.
- **`GOMAXPROCS`** set explicitly. Nomad's docker driver applies CPU shares,
  not a quota, so the Go runtime would otherwise size itself for every core
  on the client.
- **Shutdown ordering:** `--shutdown-timeout 20s` < `kill_timeout = "30s"`,
  with `shutdown_delay = "5s"` after Consul deregistration.
- **`/readyz` check through an Envoy expose path**, so the mesh pulls an
  instance with no policies loaded or one that has started draining.
- **`update { auto_revert = true }`**: a policy tree that fails to load fails
  the new alloc's startup, the deployment fails, and Nomad reverts.

If you enable rate limiting, also pass `--rate-limit-identifier identity`
(see [Running behind a service mesh](#running-behind-a-service-mesh)).

### Updating policies

After CI has synced a new checkout onto the policy volume, pick one path:

```bash
EXPECTED_DIGEST=$(garmr policy digest policies/)

# (a) Rollout: each new alloc loads at startup; a broken tree fails the
#     deployment and auto_revert restores the previous version.
nomad job run deploy/nomad/garmr-service.nomad.hcl

# (b) Reload in place: dispatch the reload job, which runs inside the mesh
#     and converges every alloc on the expected digest.
nomad job dispatch -meta digest="$EXPECTED_DIGEST" garmr-reload
```

The reload is a job, not a `curl` from CI, because the `/v1` API is reachable
only from inside the mesh. The job declares Garmr as a Connect upstream,
which load-balances across allocs, so it runs
`garmr policy reload --converge --instances N --expect-digest <digest>`:
it repeats the reload until it has seen `N` distinct allocs (by
`instance_id`, which is the Nomad alloc ID) all report the expected digest,
and exits nonzero on timeout, mismatch, or divergence. Keep the job's
`instances` variable equal to the service job's `count`.

See `deploy/nomad/README.md` for the full pipeline, sizing, and the batch
evaluation job.

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
      package policies

      example: {
        apiVersion: "policy.garmr.io/v1"
        kind: "Policy"
        metadata: { name: "example", namespace: "default" }
        spec: {
          target: resources: ["*"]
          rules: [{
            id: "r1"
            description: "env must be prod"
            severity: "high"
            expr: { match: { path: "env", equals: "prod" } }
            message: "env must be prod"
          }]
          enforcement: { action: "deny" }
        }
      }
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
  Garmr does not re-check who may call it. Intentions are service-level, so
  any service allowed to evaluate can also reach the management endpoints
  (reload, delete); keep the allow list tight.
- **Audit principal** is recorded only if the XFCC header actually reaches
  Garmr. On Consul that requires the service's protocol to be `http`
  (service-defaults on Nomad, a `ServiceDefaults` resource on Kubernetes —
  see below). Check a live record: an empty `principal` means the header is
  missing.
- **Rate limiting must key on identity.** Behind the sidecar every caller's
  address is the local Envoy, so the default `client_identifier: ip` puts
  all callers in one bucket. Set `rate_limit.client_identifier: identity`
  (`--rate-limit-identifier identity`). The Helm chart's `config.rate_limit`
  doesn't set it, so add it to your values when you enable rate limiting.

### Consul Connect

See `deploy/helm/garmr/examples/consul-connect/` for a working example. The
short version:

```bash
helm upgrade --install garmr deploy/helm/garmr \
  --namespace garmr --create-namespace \
  --set mesh.consulConnect.enabled=true
```

The chart doesn't create a `ServiceDefaults` resource. Apply one so Envoy
speaks HTTP to Garmr and injects XFCC:

```yaml
apiVersion: consul.hashicorp.com/v1alpha1
kind: ServiceDefaults
metadata:
  name: garmr
spec:
  protocol: http
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

- `/healthz` and `/livez` — liveness (cheap; both serve the same check).
  Always return 200 while the process can answer HTTP.
- `/readyz` — readiness. Returns 503 until policies are loaded. Runs only
  cheap in-process checks: the storage backend is *not* contacted, so a
  kubelet polling this endpoint does not generate backend traffic.
- `/health/deep` — comprehensive check, adding the storage backend round
  trip (is the policy volume still mounted and readable?), for operators
  and monitoring, not for probes. Returns 503 when any check fails, and —
  unlike the probe endpoints — requires the API key when one is set,
  because every call performs storage I/O.

The Helm chart wires these probes automatically; the Nomad service job
checks `/readyz` through Consul.

## High availability

Garmr instances are fully stateless. Each instance:

- Loads policies from the configured storage backend at startup, and fails
  to start if that load fails.
- Re-reads the backend on `POST /v1/policies/reload`. There is no watcher and
  no poller: reload is explicit, or happens implicitly when the pod restarts.
- Serves evaluation requests from its in-memory compiled policy set. A
  reload builds a new set and swaps it in atomically: in-flight evaluations
  finish on the old set, nothing waits on the reload, and a failed reload
  publishes nothing.

This means:

- **Multiple instances stay in sync** via the shared backend, not leader
  election. There is no cross-instance coordination to fail — and nothing
  propagates a reload either.
- **`POST /v1/policies/reload` reaches one instance.** Behind a Service or a
  mesh upstream, a single call reloads whichever instance answered and leaves
  the rest serving the old set. Reload the fleet with the CLI:

  ```bash
  # Instances you can address directly (pod IPs, Nomad alloc addresses)
  garmr policy reload \
    --servers http://10.0.0.11:8080,http://10.0.0.12:8080 \
    --expect-digest "$(garmr policy digest policies/)"

  # Through one load-balancing address (a mesh upstream)
  garmr policy reload --server http://localhost:8080 \
    --converge --instances 2 \
    --expect-digest "$(garmr policy digest policies/)"
  ```

  Both exit nonzero unless every instance reloaded and reports the expected
  digest. To check without reloading, read `digest` and `instance_id` from
  `GET /v1/policies` on each instance.
- **`DELETE /v1/policies` is also single-instance**, and is undone by the next
  reload or restart. Remove policies from git and deploy instead.
- **Expect a convergence window** when policies change: instances pick up the
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
The Nomad service job uses `--shutdown-timeout 20s` under a 30s
`kill_timeout`. Kubernetes sends SIGTERM at pod deletion and waits for
`terminationGracePeriodSeconds` (default 30). Because the drain budget and
the default grace period are the same length, either lower
`--shutdown-timeout` or raise `terminationGracePeriodSeconds` so a drain
that uses its full budget is not cut short by SIGKILL.

## Backup & restore

Policies are whatever files are on disk, so they are backed up wherever they
come from: the Git repository that renders the ConfigMap, the object-storage
bucket an init container syncs from (enable versioning there), or your usual
volume snapshot tooling for a PVC. Garmr does not implement its own backup.

Audit records are the only durable record of the mesh-verified
`principal`, so ship them off the node. The recommended posture is
`audit.path: stdout`: records stream to the process stdout, which the
platform's log capture (Nomad alloc logs, kubelet, vector/promtail/
fluent-bit) already ships — no sidecar tailer, no rotation to manage,
and application logs stay separable on stderr. The file mode
(`audit.path: /var/log/garmr/audit.log`, rotated via `max_size`,
`max_backups`, `max_age`) remains for deployments that tail files, but
note the chart mounts it on `emptyDir`, so an unshipped file dies with
the pod.
