# decisions

<!-- okfw:generated — maintained by okfw; edits here are overwritten -->

## Concepts

* [Optional TLS reinstated](optional-tls-reinstated--01a1984e4679.md) - 2026-11-01: Garmr can terminate TLS and optional mTLS itself outside a mesh; off by default, XFCC ignored under TLS, certs hot-reloaded.
* [TLS listener removed in favor of mesh mTLS](tls-listener-removed-in-favor-of-mesh-mtls--01a1984e08c1.md) - 2026-07-28: Garmr's TLS listener was deleted because Consul Connect owns mTLS; superseded on 2026-11-01 by optional TLS.

