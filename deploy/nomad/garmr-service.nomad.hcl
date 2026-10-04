# Long-lived Garmr service on Nomad inside a Consul Connect mesh.
#
# Policies come from a shared read-only volume (host volume here; swap the
# volume block for a CSI volume if that is what your cluster provides). CI/CD
# syncs the git checkout onto that volume, then either re-runs this job to
# roll the allocations (each new alloc loads at startup and FAILS CLOSED on a
# broken or empty policy tree, so auto_revert keeps the old version serving)
# or reloads in place with garmr-reload.nomad.hcl (also fail-closed: a bad
# tree returns 500 and the old set keeps serving).
#
# PREREQUISITE — apply the service-defaults config entry first:
#
#   consul config write deploy/nomad/garmr-service-defaults.hcl
#
# Without it Consul proxies this service at L4 and Envoy never injects
# X-Forwarded-Client-Cert, so every audit record ships an empty "principal"
# and identity-based rate limiting silently degrades to one shared bucket.
#
# Verify convergence after either path with garmr-reload.nomad.hcl, which
# dials Garmr as a Connect upstream. Note that the upstream load-balances
# across allocs, so convergence is checked by collecting instance_id from the
# responses rather than by addressing allocs individually — see that file.
#
# The app serves plain HTTP; Consul Connect provides mTLS and forwards the
# verified caller identity via X-Forwarded-Client-Cert (audit-logged as
# "principal"). Restrict callers with ServiceIntentions — see
# deploy/helm/garmr/examples/consul-connect/intentions.yaml for the shape.

variable "image" {
  type    = string
  default = "ghcr.io/infrashift/garmr:latest"
}

job "garmr" {
  datacenters = ["dc1"]
  type        = "service"

  group "garmr" {
    count = 2

    # Client nodes must declare this host volume:
    #   client { host_volume "garmr-policies" { path = "/opt/garmr/policies" read_only = false } }
    volume "policies" {
      type      = "host"
      source    = "garmr-policies"
      read_only = true
    }

    network {
      mode = "bridge"
    }

    # Wait after Consul deregistration before SIGTERM so in-flight routing
    # settles. /readyz also flips to 503 the instant shutdown starts.
    shutdown_delay = "5s"

    update {
      max_parallel     = 1
      health_check     = "checks"
      min_healthy_time = "10s"
      healthy_deadline = "2m"
      # Fail-closed startup makes this reliable: an alloc with a broken
      # policy tree exits nonzero, the deployment fails, and Nomad reverts
      # to the previous (working) job version.
      auto_revert = true
    }

    service {
      name = "garmr"
      port = "8080"

      connect {
        sidecar_service {}
      }

      # expose=true has Nomad configure an Envoy expose path so Consul can
      # reach /readyz without a mesh certificate. /readyz is 503 until
      # policies are loaded and again as soon as shutdown begins draining.
      #
      # Only the health check is exposed. The v1 API stays inside the mesh and
      # is reached as a Connect upstream (garmr-reload.nomad.hcl), so it is
      # governed by intentions rather than by whoever can reach the host.
      check {
        name     = "garmr-ready"
        type     = "http"
        path     = "/readyz"
        expose   = true
        interval = "10s"
        timeout  = "3s"
      }
    }

    task "garmr" {
      driver = "docker"

      config {
        image = var.image
        args = [
          "--http-addr", ":8080",
          "--policy-dir", "/etc/garmr/policies",
          # Audit records stream to stdout so Nomad's log capture (and
          # whatever ships alloc logs) carries the decision trail — the
          # only record of the mesh-verified principal — off-node.
          # Application logs go to stderr, keeping the streams separable.
          "--audit-path", "stdout",
          # Drain budget must stay below kill_timeout, or a slow drain is
          # cut short by SIGKILL.
          "--shutdown-timeout", "20s",
        ]
      }

      env {
        # Bounds CPU parallelism. Evaluations run lock-free against one
        # immutable policy snapshot, so GOMAXPROCS no longer multiplies
        # memory; it caps how many evaluations (and GC workers) run at once.
        #
        # This must be set explicitly. Nomad's docker driver applies CPU
        # *shares*, not a cpuset or quota, so GOMAXPROCS otherwise defaults
        # to the host's core count — on a 16-core client the runtime sizes
        # its scheduler and GC for 16 cores against the `cpu` reservation
        # below.
        GOMAXPROCS = "2"
      }

      volume_mount {
        volume      = "policies"
        destination = "/etc/garmr/policies"
        read_only   = true
      }

      kill_timeout = "30s"

      resources {
        cpu = 500
        # Sized for one compiled policy snapshot, two at reload peak (the
        # old set stays live until in-flight evaluations release it, while
        # CUE loads and compiles the new one), plus request buffers for
        # GOMAXPROCS=2 worth of concurrent work. Raise this with a
        # substantially larger policy tree or a higher GOMAXPROCS — the
        # failure mode is an OOM kill during reload, not a graceful error.
        memory = 512
      }
    }
  }
}
