# Garmr on Nomad + Consul Connect

Job specs for running Garmr inside a Consul service mesh on HashiCorp Nomad:

- `garmr-service.nomad.hcl` — long-lived service instances behind Connect
  sidecars.
- `garmr-batch.nomad.hcl` — parameterized dispatch job for just-in-time
  evaluation: start → load → evaluate → shut down.
- `garmr-reload.nomad.hcl` — parameterized dispatch job that reloads the
  policy set in place, from inside the mesh.
- `garmr-service-defaults.hcl` — Consul config entry. **Apply this first.**

Both patterns read policies from the same shared read-only volume, and both
rely on the same guarantee: **loading fails closed**. A policy that does not
compile or validate, or a tree that yields zero policies, fails startup (the
alloc exits nonzero) and fails reload (HTTP 500, the previous set keeps
serving). A bad deploy therefore halts loudly instead of silently shipping a
partial or empty policy set.

## Prerequisite: declare the HTTP protocol

```bash
consul config write deploy/nomad/garmr-service-defaults.hcl
```

Consul proxies a service at L4 (raw TCP) unless it declares an application
protocol, and Envoy only injects `X-Forwarded-Client-Cert` from an HTTP
connection manager. Skip this and the header never exists: every audit record
ships `"principal": ""`, and `--rate-limit-identifier identity` silently falls
back to the client IP — which behind the sidecar is the local Envoy, so every
caller shares one bucket.

Neither failure is loud. The service is healthy and decisions are still
served; the gap only shows up when you go looking for who did what.

## Transport security

Garmr serves plain HTTP. Consul Connect provides mTLS at the sidecar and
forwards the verified caller identity in `X-Forwarded-Client-Cert`; Garmr
parses the SPIFFE URI (the last entry, which is the one the sidecar
appended and vouches for) and audit-logs it as `principal`. Restrict who may
call Garmr with ServiceIntentions (see
`../helm/garmr/examples/consul-connect/intentions.yaml` for the shape —
intentions are service-level, so any service allowed to evaluate can also
call the management endpoints; keep the allow list tight).

## Rate limiting in the mesh

If you enable rate limiting, set `--rate-limit-identifier identity` (or
`rate_limit.client_identifier: identity`). The default `ip` keying is
useless behind the sidecar — every caller's `RemoteAddr` is the local
Envoy, so all services would share one bucket. `identity` keys each
bucket on the mesh-verified SPIFFE URI from the XFCC header, the same
value the audit log records as `principal`.

## Policy volume

The specs use a Nomad host volume named `garmr-policies`. Declare it on the
client nodes:

```hcl
client {
  host_volume "garmr-policies" {
    path      = "/opt/garmr/policies"
    read_only = false   # the sync job writes; garmr mounts read-only
  }
}
```

Swap the `volume` block for a CSI volume if that is what your cluster
provides. Whatever the transport, CI/CD owns the volume's content: it syncs
the reviewed git checkout there, never edits in place.

## CI/CD pipeline

```bash
# ---- CI (no server needed; all local) ----
garmr policy validate-lock policies/     # unreviewed edits fail
garmr validate policies/                 # same loader the server runs: green = server will load it
garmr test policies/ --recursive --format tap
EXPECTED_DIGEST=$(garmr policy digest policies/)

# ---- CD ----
# 1. Sync the checkout to the policy volume (rsync to the host path, CSI
#    writer job, etc.)
# 2. Pick one update path:

# (a) Rollout — preferred. Each new alloc loads at startup; a broken tree
#     fails the deployment and auto_revert restores the old version.
nomad job run deploy/nomad/garmr-service.nomad.hcl

# (b) Reload in place — no restart. Dispatch the reload job, which runs
#     inside the mesh and converges every alloc (see below):
nomad job dispatch -meta digest="$EXPECTED_DIGEST" garmr-reload
```

Both paths exit nonzero on failure, so either can gate the pipeline.

### Why reload is a job and not a curl

Garmr's `/v1` API is not reachable from outside the mesh — only `/readyz` is,
via the Envoy expose path on the health check. Admin traffic has to originate
inside the mesh, where mTLS and intentions apply, so `garmr-reload.nomad.hcl`
declares Garmr as a Connect upstream and dials it over localhost.

That upstream load-balances across allocs, and nothing in the request lets a
caller pick one. A single reload call therefore reaches one arbitrary alloc
while the others keep serving the previous policy set — and `--servers`
cannot help, because it dedupes by address and there is only one address
here: it would report a single success and exit 0 with half the fleet stale.

`--converge --instances N` handles this. Each response carries an
`instance_id`; the command repeats the reload through the same upstream until
it has seen N distinct allocs all reporting `--expect-digest`, and fails on
timeout, mismatch, or divergence. Keep `--instances` in step with the service
job's `count`.

```bash
# Register once
nomad job run deploy/nomad/garmr-reload.nomad.hcl

# Then per deploy
nomad job dispatch -meta digest="$(garmr policy digest policies/)" garmr-reload
```

### Verifying the rollout path

The rollout path has no inline check, so confirm convergence the same way —
dispatch the reload job after the rollout (a reload of already-current
policies is a no-op that still reports each alloc's digest), or read
`instance_id` and `digest` from `/v1/policies` through the same upstream.

Rollback is the same pipeline pointed at the previous git ref, or simply
`nomad job revert garmr <version>` for the rollout path.

## Just-in-time evaluation

```bash
nomad job run deploy/nomad/garmr-batch.nomad.hcl        # register once
nomad job dispatch -meta namespace=security garmr-eval input.json
```

Each dispatch starts a private Garmr, waits for `/readyz` (which holds 503
until every policy compiled), evaluates the payload, and exits with
`garmr eval`'s code: 0 allow, 1 deny. The job sets `restart { attempts = 0 }`
so that contract holds: a deny is a verdict, and Nomad's default batch restart
policy would otherwise read the nonzero exit as a crash and re-run the
evaluation three more times.

It also sets `GOMAXPROCS=2`: a one-shot evaluator serves one request and
needs no evaluation parallelism, and without it the Go runtime sizes itself
for every core on the host (see [Sizing](#sizing)).

## Shutdown behavior

On SIGTERM Garmr immediately flips `/readyz` to 503 and drains in-flight
requests for up to `--shutdown-timeout`. The service spec keeps three numbers
ordered:

1. `--shutdown-timeout 20s` — the app's drain budget,
2. `kill_timeout = "30s"` — Nomad waits at least this long before SIGKILL,
3. `shutdown_delay = "5s"` — pause after Consul deregistration before
   SIGTERM, covering routing propagation.

If you change one, keep drain budget < kill_timeout.

## Sizing

Memory follows the policy tree, not the core count. The server holds one
compiled, immutable snapshot of the policy set; evaluations read it without
locks. A reload holds two at peak: the old set stays live until in-flight
evaluations release it, while CUE loads and compiles the new one. Size
`memory` for that peak plus request buffers (up to `max_recv_size` per
in-flight request), and raise it for a substantially larger policy tree.
The failure mode is an OOM kill mid-reload, not a graceful error.

`GOMAXPROCS` caps CPU parallelism: how many evaluations, and how many GC
workers, run at once. Nomad's docker driver applies CPU *shares* rather than
a cpuset or quota, so without an explicit `GOMAXPROCS` the Go runtime sizes
itself for every core on a 16-core client regardless of the `cpu`
reservation. Both job specs set it explicitly; raise it together with `cpu`.

## Health checks

The Consul check targets `/readyz` through an Envoy expose path
(`expose = true` on the check), so the mesh pulls an instance that has no
policies loaded or has begun shutting down. Do not rely on the container
image's HEALTHCHECK under Nomad — Consul checks are the source of truth.
