// internal/server/identity.go
// Caller-identity extraction.
//
// When Garmr runs behind a sidecar proxy that terminates mTLS (Envoy / Consul
// Connect / Istio), the proxy forwards the verified client identity in a
// cleartext header, by convention X-Forwarded-Client-Cert (XFCC). This file
// parses that header and stores the SPIFFE URI SAN on the request context so
// audit log entries can record *which service* evaluated a policy, not just
// the proxy's source IP.
//
// When Garmr terminates TLS itself there is no sidecar to own that header,
// so any caller could set it. The header is then ignored and the principal
// comes only from a client certificate verified at the handshake.
package server

import (
	"context"
	"net/http"

	"github.com/infrashift/garmr/internal/tlsconf"
	"github.com/infrashift/garmr/internal/xfcc"
)

// DefaultIdentityHeader is the header proxies use to forward verified client
// identity. Overridable via Config.IdentityHeader.
const DefaultIdentityHeader = xfcc.DefaultHeader

type ctxKey int

const ctxPrincipal ctxKey = iota

// PrincipalFromContext returns the caller's identity (typically a SPIFFE URI)
// parsed from the identity header, or "" if absent or unparseable.
func PrincipalFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxPrincipal).(string); ok {
		return v
	}
	return ""
}

// identityMiddleware annotates the request context with the caller's
// principal: from the verified client certificate when Garmr terminates TLS,
// otherwise from the configured identity header. Absent or unparseable
// sources are tolerated — principal stays empty.
func (s *Server) identityMiddleware(next http.Handler) http.Handler {
	header := s.config.IdentityHeader
	if header == "" {
		header = DefaultIdentityHeader
	}
	principalOf := func(r *http.Request) string {
		return xfcc.ParseSPIFFEIdentity(r.Header.Values(header))
	}
	if s.tls != nil {
		principalOf = func(r *http.Request) string { return tlsconf.PeerIdentity(r.TLS) }
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal := principalOf(r); principal != "" {
			r = r.WithContext(context.WithValue(r.Context(), ctxPrincipal, principal))
		}
		next.ServeHTTP(w, r)
	})
}
