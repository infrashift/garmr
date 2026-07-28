# Long-lived Garmr service on Nomad inside a Consul Connect mesh.
#
# Policies come from a shared read-only volume (host volume here; swap the
# volume block for a CSI volume if that is what your cluster provides). CI/CD
# syncs the git checkout onto that volume, then either re-runs this job to
# roll the allocations (each new alloc loads at startup and FAILS CLOSED on a
# broken or empty policy tree, so auto_revert keeps the old version serving)
# or calls POST /v1/policies/reload on every alloc (also fail-closed: a bad
# tree returns 500 and the old set keeps serving).
#
# Verify convergence after either path:
#   garmr policy digest policies/                          # in CI, from git
#   curl -s http://<alloc>:8080/v1/policies | jq -r .digest  # per alloc
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
          # Drain budget must stay below kill_timeout, or a slow drain is
          # cut short by SIGKILL.
          "--shutdown-timeout", "20s",
        ]
      }

      volume_mount {
        volume      = "policies"
        destination = "/etc/garmr/policies"
        read_only   = true
      }

      kill_timeout = "30s"

      resources {
        cpu    = 500
        memory = 256
      }
    }
  }
}
