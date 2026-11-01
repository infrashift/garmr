---
id: "01a1984e-08c1-7abb-8307-f716ee49c2bb"
title: "TLS listener removed in favor of mesh mTLS"
type: "note"
tags:
  - "tls"
  - "security"
  - "deployment"
  - "superseded"
created: "2026-11-01T12:10:13-06:00"
timestamp: "2026-11-01T12:10:44-06:00"
description: "2026-07-28: Garmr's TLS listener was deleted because Consul Connect owns mTLS; superseded on 2026-11-01 by optional TLS."
status: "deprecated"
sources:
  - resource: "git:83b45af"
    title: "Phase D: readiness reflects shutdown; delete the TLS listener"
---

# TLS listener removed in favor of mesh mTLS

## Decision (2026-07-28, commit 83b45af)

During the pre-production hardening pass (Phase D) for the Nomad + Consul Connect deployment, the server-side TLS listener was deleted outright. The commit removed:

- the `--tls`, `--tls-cert` and `--tls-key` flags, the `tls.*` config keys, and `Config.EnableTLS/TLSCert/TLSKey`;
- the `ListenAndServeTLS` branch;
- the rate limiter's `cert` client identifier (the CN of the peer certificate). It could not be reached, because the server never terminated TLS.

Rationale recorded in the commit: Garmr runs as plain HTTP inside a service mesh that owns mTLS. Consul Connect terminates mTLS at the sidecar and forwards the verified identity in the XFCC header. Deployments outside a mesh were to put a TLS-terminating proxy in front of the server.

An earlier decision (2026-07-09, TODO.md) had already rejected built-in mTLS for the same reason.

## Status

Superseded by [Optional TLS reinstated](./optional-tls-reinstated--01a1984e4679.md). The mesh posture this decision describes is still the recommended production deployment, and TLS stays off there.
