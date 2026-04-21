# Garmr on Consul Connect

This example installs Garmr as a Connect-enabled service in a `consul-k8s`
cluster and exposes it to a pair of callers via ServiceIntentions.

## Prerequisites

- `consul-k8s` installed with `connectInject.enabled=true`.
- Transparent proxy supported and enabled.
- Garmr's Helm chart checked out at `deploy/helm/garmr/` (this repo).

## Install Garmr

```bash
helm upgrade --install garmr deploy/helm/garmr \
  --namespace garmr --create-namespace \
  --set mesh.consulConnect.enabled=true \
  --set tracing.endpoint=otel-collector.observability.svc.cluster.local:4317 \
  --set config.auth.api_key="" \
  -f values-policies.yaml
```

The `mesh.consulConnect.enabled=true` flag adds the
`consul.hashicorp.com/connect-inject: "true"` annotation, prompting the
Consul connect-inject webhook to mutate the pod and attach an Envoy sidecar
that terminates mTLS.

## Intentions

Once the Garmr service is registered, deny everything by default and allow
only specific callers:

```yaml
# intentions.yaml
apiVersion: consul.hashicorp.com/v1alpha1
kind: ServiceIntentions
metadata:
  name: garmr
spec:
  destination:
    name: garmr
  sources:
    - name: policy-gateway
      action: allow
    - name: ci-runner
      action: allow
    - name: "*"
      action: deny
```

Apply with `kubectl apply -f intentions.yaml`.

## Caller identity in audit logs

Envoy's connect-inject sidecar forwards the verified client SPIFFE identity
in `X-Forwarded-Client-Cert`. Garmr parses the `URI=` field out of that
header and records it as `principal` on every audit log entry. No extra
configuration is required as long as the mesh is in front of Garmr.

Verify the audit log on a running pod:

```bash
kubectl -n garmr exec -it deploy/garmr -- tail -1 /var/log/garmr/audit.log | jq .principal
# -> "spiffe://your-cluster/ns/apps/sa/policy-gateway"
```

## Calling Garmr from another Connect service

With transparent proxy enabled you call Garmr by its Kubernetes DNS — the
sidecar transparently applies mTLS:

```bash
curl -sf http://garmr.garmr.svc.cluster.local:8080/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"input": {"env": "prod"}}'
```

## Metrics scraping inside the mesh

The `/metrics` endpoint is exempt from Garmr's API-key auth and unaffected by
Connect intentions (Envoy allows prometheus scraping on an exposed port).
Expose it with the standard Consul annotation:

```yaml
annotations:
  consul.hashicorp.com/prometheus-scrape-port: "8080"
  consul.hashicorp.com/prometheus-scrape-path: "/metrics"
```

Add these to `podAnnotations` in your Garmr values.yaml.
