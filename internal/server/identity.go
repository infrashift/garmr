// internal/server/identity.go
// Caller-identity extraction from a service-mesh header.
//
// When Garmr runs behind a sidecar proxy that terminates mTLS (Envoy / Consul
// Connect / Istio), the proxy forwards the verified client identity in a
// cleartext header, by convention X-Forwarded-Client-Cert (XFCC). This file
// parses that header and stores the SPIFFE URI SAN on the request context so
// audit log entries can record *which service* evaluated a policy, not just
// the proxy's source IP.
package server

import (
	"context"
	"net/http"

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

// identityMiddleware parses the configured identity header and annotates the
// request context with the caller's principal. Unknown / absent headers are
// tolerated — principal stays empty.
func (s *Server) identityMiddleware(next http.Handler) http.Handler {
	header := s.config.IdentityHeader
	if header == "" {
		header = DefaultIdentityHeader
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal := xfcc.ParseSPIFFEIdentity(r.Header.Values(header)); principal != "" {
			r = r.WithContext(context.WithValue(r.Context(), ctxPrincipal, principal))
		}
		next.ServeHTTP(w, r)
	})
}
