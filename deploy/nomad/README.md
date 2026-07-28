# Garmr on Nomad + Consul Connect

Job specs for running Garmr inside a Consul service mesh on HashiCorp Nomad:

- `garmr-service.nomad.hcl` — long-lived service instances behind Connect
  sidecars.
- `garmr-batch.nomad.hcl` — parameterized dispatch job for just-in-time
  evaluation: start → load → evaluate → shut down.

Both patterns read policies from the same shared read-only volume, and both
rely on the same guarantee: **loading fails closed**. A policy that does not
compile or validate, or a tree that yields zero policies, fails startup (the
alloc exits nonzero) and fails reload (HTTP 500, the previous set keeps
serving). A bad deploy therefore halts loudly instead of silently shipping a
partial or empty policy set.

## Transport security

Garmr serves plain HTTP. Consul Connect provides mTLS at the sidecar and
forwards the verified caller identity in `X-Forwarded-Client-Cert`; Garmr
parses the SPIFFE URI and audit-logs it as `principal`. Restrict who may call
Garmr with ServiceIntentions (see
`../helm/garmr/examples/consul-connect/intentions.yaml` for the shape —
intentions are service-level, so any service allowed to evaluate can also
call the management endpoints; keep the allow list tight).

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

# (b) Reload in place — no restart, but the endpoint mutates ONE process,
#     so hit every alloc, not the service VIP:
nomad job allocs -json garmr | jq -r '.[] | select(.ClientStatus=="running") | .ID' |
  while read -r alloc; do
    nomad alloc exec "$alloc" wget -q -O- --post-data='' http://127.0.0.1:8080/v1/policies/reload
  done

# ---- Verify convergence (either path) ----
ACTUAL=$(curl -s http://garmr.service.consul:8080/v1/policies | jq -r .digest)
test "$EXPECTED_DIGEST" = "$ACTUAL"
```

Rollback is the same pipeline pointed at the previous git ref, or simply
`nomad job revert garmr <version>` for the rollout path.

## Just-in-time evaluation

```bash
nomad job run deploy/nomad/garmr-batch.nomad.hcl        # register once
nomad job dispatch -meta namespace=security garmr-eval input.json
```

Each dispatch starts a private Garmr, waits for `/readyz` (which holds 503
until every policy compiled), evaluates the payload, and exits with
`garmr eval`'s code: 0 allow, 1 deny. The job sets `GOMAXPROCS=2` because
startup compiles the policy set once per internal replica
(K = min(GOMAXPROCS, 8)); a one-shot evaluator wants a small K for fast cold
starts, not evaluation parallelism.

## Shutdown behavior

On SIGTERM Garmr immediately flips `/readyz` to 503 and drains in-flight
requests for up to `--shutdown-timeout`. The service spec keeps three numbers
ordered:

1. `--shutdown-timeout 20s` — the app's drain budget,
2. `kill_timeout = "30s"` — Nomad waits at least this long before SIGKILL,
3. `shutdown_delay = "5s"` — pause after Consul deregistration before
   SIGTERM, covering routing propagation.

If you change one, keep drain budget < kill_timeout.

## Health checks

The Consul check targets `/readyz` through an Envoy expose path
(`expose = true` on the check), so the mesh pulls an instance that has no
policies loaded or has begun shutting down. Do not rely on the container
image's HEALTHCHECK under Nomad — Consul checks are the source of truth.
