---
id: "01a205ae-5632-7448-97d9-2247dcf05f95"
title: "Releases are tag-driven GitHub releases with provenance"
type: "decision"
tags:
  - "release"
  - "ci"
  - "supply-chain"
created: "2026-11-22T17:54:01-06:00"
timestamp: "2026-11-22T17:54:01-06:00"
description: "2026-11-22: garmr ships as cross-compiled linux/darwin amd64/arm64 archives built by a v* tag workflow, smoke-tested natively, with SHA256SUMS and SLSA provenance; v0.1.0 is the first release."
---

# Releases are tag-driven GitHub releases with provenance

## Context

garmr had no published releases. Users built from source or used the container image. The old `make release` target built one linux/amd64 tarball and ran the tests and linters first, but nothing published it. The sibling project whac-a-leak already ships tag-driven releases, and garmr follows the same pattern.

## Decision

- A pushed `vX.Y.Z` tag runs `.github/workflows/release.yml`.
- `make dist` builds one archive per platform: `garmr_<version>_<os>_<arch>.tar.gz` with `garmr`, `garmr-server`, `config.example.yaml`, `README.md` and `LICENSE`. Pure Go (`CGO_ENABLED=0`), `-trimpath`, stripped, with the version and commit set through ldflags. Platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.
- A smoke job runs each archive on a native runner (Ubuntu amd64 and arm64, macOS arm64, and macOS amd64 through Rosetta 2). It checks `garmr version` against the tag, starts `garmr-server` on the example policies, checks `garmr health` reports the tag, and expects an ALLOW (exit 0) and a DENY (exit 1) evaluation.
- The release job writes `SHA256SUMS`, attests SLSA build provenance (`actions/attest-build-provenance`), and runs `gh release create --verify-tag --generate-notes`.
- `make release VERSION=vX.Y.Z` builds the same archives locally. It no longer runs `test` and `lint`; the CI workflow gates `main` before a tag.

## Not in scope

- Windows archives.
- Publishing the multi-arch container image on a tag (`make docker-release` stays manual).

## Related

- [Go 1.26.11 govulncheck finding](/security/govulncheck-clean-after-go-1-26-11-bump-2026-11-11--01a1ca400faa.md): v0.1.0 is built with the patched toolchain from `go.mod`.
