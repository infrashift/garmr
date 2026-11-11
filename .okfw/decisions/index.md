# decisions

<!-- okfw:generated — maintained by okfw; edits here are overwritten -->

## Concepts

* [Exceptions can waive rules and individual findings](exceptions-can-waive-rules-and-individual-findings--01a1ca3734c7.md) - 2026-11-11: exceptions gained rules (skip named rules) and findings {as, where} (waive forEach elements, e.g. by producer fingerprint); waived elements are always reported, and a failing selector waives nothing.
* [Optional TLS reinstated](optional-tls-reinstated--01a1984e4679.md) - 2026-11-01: Garmr can terminate TLS and optional mTLS itself outside a mesh; off by default, XFCC ignored under TLS, certs hot-reloaded.
* [TLS listener removed in favor of mesh mTLS](tls-listener-removed-in-favor-of-mesh-mtls--01a1984e08c1.md) - 2026-07-28: Garmr's TLS listener was deleted because Consul Connect owns mTLS; superseded on 2026-11-01 by optional TLS.
* [Vizzini integration stays HTTP/JSON](vizzini-integration-stays-http-json--01a1ca253787.md) - 2026-11-11: garmr integrates with the Vizzini PR reviewer as a data contract over HTTP/JSON or in-process eval, not gRPC; six garmr changes on feature/improvements-for-vizzini support it.
* [forEach allowMissing is opt-in](foreach-allowmissing-is-opt-in--01a1ca253796.md) - 2026-11-11: an absent or null forEach list still fails by default; allowMissing: true treats it as empty, chosen over folding missing into allowEmpty, which would have failed open.
* [inputSchema is enforced at load and in the CLI, not per request](inputschema-is-enforced-at-load-and-in-the-cli-not-per-request--01a1ca30fa83.md) - 2026-11-11: spec.inputSchema checks rule paths at every policy load and validates input only in garmr eval --local and garmr test; the server never compiles CUE per request.

