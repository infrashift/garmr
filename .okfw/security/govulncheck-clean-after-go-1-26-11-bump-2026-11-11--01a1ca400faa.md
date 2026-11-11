---
id: "01a1ca40-0faa-7a07-9788-15d1ea9c5107"
title: "govulncheck clean after Go 1.26.11 bump 2026-11-11"
type: "Finding"
tags:
  - "security"
  - "dependencies"
  - "go-toolchain"
created: "2026-11-11T04:55:58-06:00"
timestamp: "2026-11-11T04:55:58-06:00"
description: "2026-11-11: go.mod moved to go 1.26.11 and otel/grpc/x/net were upgraded; govulncheck went from 22 reachable vulnerabilities to none, and golangci-lint v1.64.8 still builds under it."
generated:
  by: "claude-code/opus-5.5"
  at: "2026-11-11T04:55:58-06:00"
---

# govulncheck clean after Go 1.26.11 bump 2026-11-11

# govulncheck clean after Go 1.26.11 bump 2026-11-11

Resolves [govulncheck baseline 2026-11-01](./govulncheck-baseline-2026-11-01--01a198ab88a4.md). The fix shipped on branch `feature/improvements-for-vizzini`.

## Before

`govulncheck ./...` (latest govulncheck, `GOTOOLCHAIN=go1.25.14`, to match CI and the Containerfile) found **22 reachable** vulnerabilities. That is one more than the baseline: a net/http fix that needs **go1.26.11**. The other 21 were as recorded: crypto/x509, crypto/tls, net/http, net/textproto and html/template from the stdlib, plus x/net, x/text, grpc and otel.

## Change

- `go.mod`: `go 1.25.14` → `go 1.26.11`, the newest 1.26 patch on the date. `go1.26.12` was not available. The Containerfile pins `golang:1.26.11-alpine`. CI uses `go-version-file: go.mod`.
- Module upgrades:
  - otel, sdk, trace and the OTLP exporters v1.38.0 → **v1.45.0**
  - otelhttp contrib v0.63.0 → **v0.70.0** (the release paired with otel v1.45)
  - grpc v1.75.0 → **v1.83.2**
  - x/net → **v0.62.0**
  - x/text → **v0.43.0**. Pinning x/text alone at v0.39.0 is impossible because x/net v0.60+ requires ≥ v0.42.

  grpc v1.83.2 and x/net v0.62.0 also clear three *unreachable* findings: GO-2026-6443, -6866 and -6860.

## After

`govulncheck -show verbose ./...` under go1.26.11 reports **No vulnerabilities found**.

Verified on the bump commit:
- the race suite
- golangci-lint v1.64.8 built with go1.26.11 (as CI's `install-mode: goinstall` does): 0 issues
- the podman image build and `/readyz` smoke test
- parity between local and server eval on the review fixtures

## Gotcha

The workstation toolchain is **go1.27.3**. Tools built or run with it give false failures here:
- golangci-lint v1.64.8 cannot read go1.27 export data ("export data version 5 is greater than maximum supported version 2").
- A govulncheck built with go1.26 cannot load go1.27 stdlib sources.

Run checks with `GOTOOLCHAIN=go1.26.11` (the go.mod version) so they reproduce CI.
