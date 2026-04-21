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
	"strings"
)

// DefaultIdentityHeader is the header proxies use to forward verified client
// identity. Overridable via Config.IdentityHeader.
const DefaultIdentityHeader = "X-Forwarded-Client-Cert"

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
		if principal := parseSPIFFEIdentity(r.Header.Values(header)); principal != "" {
			r = r.WithContext(context.WithValue(r.Context(), ctxPrincipal, principal))
		}
		next.ServeHTTP(w, r)
	})
}

// parseSPIFFEIdentity walks one or more XFCC header values and returns the
// first URI= field (quoted or unquoted). Returns "" if none found.
//
// XFCC format (Envoy):
//
//	By=<downstream>;Hash=<hex>;URI=<spiffe-uri>;DNS=<san>;Subject="..."
//
// Multiple certs in the chain are comma-separated at the top level. Values
// containing delimiters or backslashes are double-quoted.
func parseSPIFFEIdentity(values []string) string {
	for _, v := range values {
		for _, entry := range splitXFCC(v, ',') {
			for _, field := range splitXFCC(entry, ';') {
				key, value, ok := splitKV(field)
				if !ok {
					continue
				}
				if strings.EqualFold(key, "URI") && value != "" {
					return value
				}
			}
		}
	}
	return ""
}

// splitXFCC splits s on sep, respecting double-quoted runs.
func splitXFCC(s string, sep byte) []string {
	var out []string
	var buf strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			buf.WriteByte(c)
		case c == sep && !inQuote:
			out = append(out, strings.TrimSpace(buf.String()))
			buf.Reset()
		default:
			buf.WriteByte(c)
		}
	}
	if buf.Len() > 0 || len(out) == 0 {
		out = append(out, strings.TrimSpace(buf.String()))
	}
	return out
}

// splitKV splits "key=value" — returning the unquoted value when quoted.
func splitKV(s string) (string, string, bool) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", "", false
	}
	k := strings.TrimSpace(s[:i])
	v := strings.TrimSpace(s[i+1:])
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return k, v, true
}
