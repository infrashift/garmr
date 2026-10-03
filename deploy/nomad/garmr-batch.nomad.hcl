# Just-in-time Garmr evaluation as a parameterized Nomad dispatch job.
#
# Each dispatch starts a private Garmr instance, loads the policies from the
# shared volume (the same volume the long-lived service uses), evaluates the
# payload, and shuts down. Startup fails closed: a broken or empty policy
# tree exits nonzero before anything is evaluated, and /readyz holds 503
# until the set is loaded, so the eval loop below cannot race a partial load.
#
# Dispatch with:
#   nomad job dispatch -meta namespace=security garmr-eval input.json
#
# The dispatch exit code follows garmr eval: 0 allow, 1 deny — wire it
# straight into the calling pipeline.

variable "image" {
  type    = string
  default = "ghcr.io/infrashift/garmr:latest"
}

job "garmr-eval" {
  datacenters = ["dc1"]
  type        = "batch"

  parameterized {
    payload       = "required"
    meta_optional = ["namespace"]
  }

  group "eval" {
    # A deny is a verdict, not a task failure.
    #
    # `garmr eval` exits 1 on DENY and the wrapper propagates it. Nomad's
    # default batch restart policy (attempts = 3, mode = "fail") reads that
    # nonzero exit as a crash and re-runs the evaluation three more times,
    # plus a reschedule — so a single denied artifact was evaluated four
    # times, each re-compiling the whole policy set, and the pipeline saw
    # "failed" rather than the deny/allow contract documented above.
    restart {
      attempts = 0
      mode     = "fail"
    }

    reschedule {
      attempts  = 0
      unlimited = false
    }

    volume "policies" {
      type      = "host"
      source    = "garmr-policies"
      read_only = true
    }

    network {
      mode = "bridge"
    }

    task "eval" {
      driver = "docker"

      dispatch_payload {
        file = "input.json"
      }

      config {
        image      = var.image
        entrypoint = ["/bin/sh", "-c"]
        args       = [<<-EOF
          set -e
          /usr/local/bin/garmr-server \
            --http-addr 127.0.0.1:8080 \
            --policy-dir /etc/garmr/policies \
            --audit=false &
          SERVER=$!

          # Wait for readiness: /readyz is 200 only once every policy
          # compiled. Startup failure kills the loop via the wait below.
          i=0
          until wget -q -O /dev/null http://127.0.0.1:8080/readyz; do
            i=$((i+1))
            if [ "$i" -ge 50 ] || ! kill -0 $SERVER 2>/dev/null; then
              echo "garmr-server never became ready" >&2
              wait $SERVER || true
              exit 2
            fi
            sleep 0.2
          done

          set +e
          /usr/local/bin/garmr eval \
            --server http://127.0.0.1:8080 \
            --input "$${NOMAD_TASK_DIR}/input.json" \
            $${NOMAD_META_namespace:+--namespace "$${NOMAD_META_namespace}"} \
            --request-id "nomad-$${NOMAD_ALLOC_ID}" \
            -o json
          RC=$?
          set -e

          kill -TERM $SERVER
          wait $SERVER || true
          exit $RC
        EOF
        ]
      }

      volume_mount {
        volume      = "policies"
        destination = "/etc/garmr/policies"
        read_only   = true
      }

      env {
        # Each internal policy replica compiles the full set at startup
        # (K = min(GOMAXPROCS, 8) CUE contexts). A one-shot evaluator does
        # not need evaluation parallelism — keeping K small cuts cold-start
        # compile time roughly proportionally.
        GOMAXPROCS = "2"
      }

      resources {
        cpu    = 500
        memory = 256
      }
    }
  }
}
