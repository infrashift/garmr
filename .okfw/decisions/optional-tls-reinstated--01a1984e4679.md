---
id: "01a1984e-4679-72f3-bf10-0a387e90e443"
title: "Optional TLS reinstated"
type: "note"
tags:
  - "tls"
  - "mtls"
  - "security"
  - "deployment"
created: "2026-11-01T12:10:29-06:00"
timestamp: "2026-11-01T12:10:44-06:00"
description: "2026-11-01: Garmr can terminate TLS and optional mTLS itself outside a mesh; off by default, XFCC ignored under TLS, certs hot-reloaded."
sources:
  - resource: "plans/mighty-brewing-bunny.md (approved 2026-11-01)"
    title: "Approved implementation plan"
---

# Optional TLS reinstated

## Decision (2026-11-01, user-approved plan, branch feat/optional-tls)

Garmr now also has to run **outside a service mesh**, so TLS is back as an **opt-in** setting. It reverses [TLS listener removed in favor of mesh mTLS](./tls-listener-removed-in-favor-of-mesh-mtls--01a1984e08c1.md) for the non-mesh case only. Inside Consul Connect, TLS stays **off** and the XFCC identity path is unchanged.

Scope choices made by the user:

- **Server TLS plus optional mTLS.** Setting `tls.client_ca_file` enables mTLS. The verified certificate's URI SAN becomes the audit `principal` and the `rate_limit.client_identifier: identity` key.
- **Hot reload from disk.** Rotation needs no restart. A failed reload keeps the last good certificate serving.
- **CLI flags `--ca-cert`, `--client-cert`, `--client-key`.** These are also available as `GARMR_TLS_*` env vars and `tls.*` config-file keys. `--insecure-skip-verify` was deliberately **not** added, because it is easy to misuse in CI.

## Design rules (what the code enforces, and why)

- **The XFCC header is ignored whenever TLS is enabled.** When Garmr terminates TLS, no sidecar sits in front to set or strip that header, so any caller could forge it. Identity comes only from `r.TLS.VerifiedChains`. `tlsconf.PeerIdentity` never reads `PeerCertificates`. One function, `Server.principalOf`, picks the trusted source. It feeds both the audit principal and the rate limiter (`ratelimit.Config.Identity`), so the two cannot drift apart. This came out of the PR #1 review.
- **The handshake uses `VerifyClientCertIfGiven`, and the app layer enforces the certificate.** Kubelet and Consul HTTPS probes present no client certificate, so `RequireAndVerifyClientCert` would fail every probe and pull the instance from service. A presented certificate is still fully verified at the handshake, so a cert from a foreign CA fails the handshake. `authMiddleware` returns `401 client certificate required` on non-exempt paths, using the same exemption list as the API key (probe paths plus `AuthExemptPaths`).
- **The API key and mTLS combine with AND** when both are configured.
- **Startup fails closed.** These stop the server before it listens: a missing or mismatched cert/key, a CA file with no certs, an invalid `min_version`, and `identity` rate limiting with TLS on but no client CA. TLS files configured while TLS is disabled only produce a warning.
- **Rotation is detected by polling (mtime, size), not fsnotify.** Renderers (Nomad templates, kubelet secret volumes) swap files by rename or symlink, which inotify handles poorly. Stamps of a broken state are remembered, including a sentinel for a missing file. A half-written rotation, or a file deleted for a while, logs one warning and then recovers once the files are back.
- **`GetConfigForClient` serves an atomic snapshot**, so certificate and client CA rotate together. The snapshot must restate `NextProtos` (`h2`, `http/1.1`), because a config returned from `GetConfigForClient` replaces the server's config and HTTP/2 would otherwise be lost silently.
- **A combined PEM (cert + chain + key in one file) works for both `cert_file` and `key_file`.** This is the recommended Nomad recipe: one `pkiCert` template renders one file atomically. Two templates would issue two different certificates.
- **The Helm chart refuses `tls.enabled` together with `mesh.consulConnect.enabled`.** It also refuses `tls.secretName` or `tls.clientCASecretName` set while `tls.enabled` is false. Otherwise it would render a plaintext pod that only looks configured for mTLS. It mounts Secrets as directories, never with `subPath`, because `subPath` mounts never receive renewals.

## Where it lives

- `internal/tlsconf` (Reloader, `PeerIdentity`, `HasVerifiedPeer`), plus `internal/tlsconf/tlstest` for minting certificates in tests.
- `internal/server/server.go` (`Config.TLSEnabled`/`Config.TLS`, the listener, the mTLS check in `authMiddleware`) and `identity.go`.
- `internal/ratelimit` (`Config.Identity`, supplied by the server).
- Toolchain: go.mod requires go 1.25.14. Go versions before 1.25.7 have GO-2026-4337, which lets resumed TLS sessions bypass a rotated client CA. Known vulnerabilities that remain: [govulncheck baseline 2026-11-01](/security/govulncheck-baseline-2026-11-01--01a198ab88a4.md).
- `internal/client` (`Config.CACertFile/ClientCertFile/ClientKeyFile`). TLS options on an `http://` address are an error, never a silent plaintext fallback.
- User docs: `reference/configuration.md` § Transport Security (TLS), `operations/deploying.md` § Running outside a mesh, `guides/cli.md` § TLS, `deploy/nomad/README.md`.
