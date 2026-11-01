---
id: "01a198ab-88a4-7dbf-8d63-6951b78fc756"
title: "govulncheck baseline 2026-11-01"
type: "Finding"
tags:
  - "security"
  - "dependencies"
  - "go-toolchain"
created: "2026-11-01T13:52:20-06:00"
timestamp: "2026-11-01T13:52:26-06:00"
description: "govulncheck found 21 reachable vulnerabilities on Go 1.25.14 and the pinned otel/grpc/x/net/x/text versions; fixing them needs Go 1.26 and module upgrades."
sources:
  - resource: "https://github.com/infrashift/garmr/pull/1"
---

# govulncheck baseline 2026-11-01

## What was observed

`govulncheck ./...` ran on 2026-11-01 against branch `feat/optional-tls`
(PR #1). Before the run, go.mod's `go` directive had moved from 1.25.3 to
1.25.14. That move fixed GO-2026-4337 ("Unexpected session resumption in
crypto/tls", fixed in go1.25.7), the only finding the PR #1 code review
raised.

The run still reported **21 vulnerabilities reachable from Garmr's code**.
All of them are also present on `main`:

| Where | Advisories (examples) | Fixed in |
|---|---|---|
| Standard library: crypto/x509, crypto/tls, net/http, net/textproto, html/template | GO-2026-6809 (distrust compromised intermediates), GO-2026-6607 (malformed ECH outer extensions), GO-2026-6599/6600, GO-2026-6603–6613 | go1.26.9 / go1.26.10 only |
| golang.org/x/net | GO-2026-6603–6617, GO-2026-5026 | v0.60.0 |
| golang.org/x/text | GO-2026-5970 | v0.39.0 |
| google.golang.org/grpc | GO-2026-6061, GO-2026-6348 | v1.83.1 |
| go.opentelemetry.io/otel, sdk, OTLP exporters | GO-2026-4394, 4985, 5426, 5506, 6505 | v1.45.0 |

## Analysis — not part of the scan output

- The standard-library fixes ship only in Go 1.26. Go 1.25 no longer
  gets them, so staying on 1.25 means carrying them indefinitely.
- GO-2026-6607 (crypto/tls) and GO-2026-6809 (crypto/x509) matter more
  now that Garmr can terminate TLS itself. See
  [Optional TLS reinstated](/decisions/optional-tls-reinstated--01a1984e4679.md).
  Inside Consul Connect the Envoy sidecar terminates TLS, so these two
  bite only in the opt-in non-mesh mode.
- Planned remedy: a dedicated PR that moves the module to Go 1.26 and
  upgrades the modules above. It is tracked in TODO.md under "Toolchain
  and dependency vulnerabilities (2026-11-01)".
