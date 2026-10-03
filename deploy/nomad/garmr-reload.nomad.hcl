# Reload Garmr's policy set in place, from inside the mesh.
#
# Dispatch after CI has synced the policy volume:
#
#   nomad job dispatch -meta digest="$(garmr policy digest policies/)" garmr-reload
#
# Exit code is the result: 0 only when every instance acknowledged the
# expected digest, nonzero otherwise. Wire it straight into the pipeline.
#
# WHY A JOB RATHER THAN A curl FROM CI
#
# Garmr's v1 API is not exposed outside the mesh — only /readyz is, via the
# Envoy expose path on the health check. Admin traffic therefore has to
# originate inside the mesh, where mTLS and ServiceIntentions apply. This job
# declares Garmr as a Connect upstream and talks to it over localhost.
#
# WHY --converge RATHER THAN --servers
#
# A Connect upstream load-balances across every healthy alloc, and nothing in
# the request lets the caller pick one. A single reload call therefore reaches
# one arbitrary alloc; the others keep serving the previous policy set. The
# plain fan-out (--servers) cannot help — it dedupes by address, and there is
# only one address here, so it would report a single success and exit 0 with
# half the fleet stale.
#
# --converge repeats the reload through the same upstream, collecting the
# instance_id each response carries, and succeeds only once it has seen
# --instances distinct allocs all reporting the expected digest. Keep
# --instances in step with the service job's `count`.

variable "image" {
  type    = string
  default = "ghcr.io/infrashift/garmr:latest"
}

variable "instances" {
  type        = number
  default     = 2
  description = "Number of Garmr allocs to converge; must match the service job's count."
}

job "garmr-reload" {
  datacenters = ["dc1"]
  type        = "batch"

  parameterized {
    payload       = "forbidden"
    meta_required = ["digest"]
  }

  group "reload" {
    # A reload that fails is a real failure to report, not something to retry
    # silently: the pipeline needs the exit code, and a retry would mask a
    # genuinely broken policy tree behind an eventual success.
    restart {
      attempts = 0
      mode     = "fail"
    }

    reschedule {
      attempts  = 0
      unlimited = false
    }

    network {
      mode = "bridge"
    }

    service {
      name = "garmr-reload"

      connect {
        sidecar_service {
          proxy {
            upstreams {
              destination_name = "garmr"
              local_bind_port  = 8080
            }
          }
        }
      }
    }

    task "reload" {
      driver = "docker"

      config {
        image      = var.image
        entrypoint = ["/usr/local/bin/garmr"]
        args = [
          "policy", "reload",
          # The sidecar's local bind for the garmr upstream. Traffic leaves
          # this task as plain HTTP on loopback and is mTLS'd by Envoy.
          "--server", "http://localhost:8080",
          "--converge",
          "--instances", "${var.instances}",
          "--expect-digest", "${NOMAD_META_digest}",
          "--converge-timeout", "2m",
          "-o", "json",
        ]
      }

      resources {
        cpu    = 200
        memory = 128
      }
    }
  }
}
