# Consul service-defaults for Garmr.
#
# Apply BEFORE running garmr-service.nomad.hcl:
#
#   consul config write deploy/nomad/garmr-service-defaults.hcl
#
# Why this is required, not optional:
#
# Consul's sidecar proxies at L4 (raw TCP) unless the service declares an
# application protocol. Envoy only injects X-Forwarded-Client-Cert from an
# HTTP connection manager, so with the default TCP protocol the header never
# exists. Garmr keeps working — but:
#
#   * every audit record ships "principal": "", which is the entire reason the
#     mesh identity plumbing exists; and
#   * --rate-limit-identifier identity finds no header and falls back to the
#     client IP, which behind a sidecar is the local Envoy — collapsing every
#     caller into a single shared bucket.
#
# Neither failure is loud. The service looks healthy, decisions are still
# served, and the gap only shows up when you go looking for who did what.
#
# Setting protocol = "http" also gets you L7 features the deployment relies
# on: per-path Envoy expose (the /readyz health check) and HTTP-aware
# retry/timeout behaviour on the upstream used by garmr-reload.nomad.hcl.

Kind     = "service-defaults"
Name     = "garmr"
Protocol = "http"
