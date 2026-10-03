// Package xfcc parses the X-Forwarded-Client-Cert header a service-mesh
// sidecar (Envoy / Consul Connect / Istio) sets after terminating mTLS. Both
// the server's identity middleware (audit principal) and the rate limiter's
// identity keying consume it, so the parsing lives in one place.
package xfcc

import "strings"

// DefaultHeader is the header proxies use to forward verified client
// identity.
const DefaultHeader = "X-Forwarded-Client-Cert"

// ParseSPIFFEIdentity walks one or more XFCC header values and returns the
// LAST URI= field (quoted or unquoted). Returns "" if none found.
//
// XFCC format (Envoy):
//
//	By=<downstream>;Hash=<hex>;URI=<spiffe-uri>;DNS=<san>;Subject="..."
//
// Multiple certs in the chain are comma-separated at the top level. Values
// containing delimiters or backslashes are double-quoted.
//
// The last entry is the one to trust, and reading the first was a spoofing
// hole. Under Envoy's APPEND_FORWARD mode — what a mesh uses when it wants to
// preserve an existing chain — the sidecar appends its own verified entry
// after whatever the downstream already sent, so a caller that supplies its
// own X-Forwarded-Client-Cert header wins a first-match parse and forges the
// principal on every decision it makes. Reading the last entry takes the
// sidecar's, and is identical under SANITIZE_SET (which leaves exactly one
// entry), so this is correct regardless of how the proxy is configured.
//
// This mirrors how the rate limiter treats X-Forwarded-For, which likewise
// believes only the right-most entry — the one its trusted proxy vouches for.
func ParseSPIFFEIdentity(values []string) string {
	identity := ""
	for _, v := range values {
		for _, entry := range split(v, ',') {
			for _, field := range split(entry, ';') {
				key, value, ok := splitKV(field)
				if !ok {
					continue
				}
				if strings.EqualFold(key, "URI") && value != "" {
					identity = value
				}
			}
		}
	}
	return identity
}

// split splits s on sep, respecting double-quoted runs.
func split(s string, sep byte) []string {
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
