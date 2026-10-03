package xfcc

import "testing"

func TestParseSPIFFEIdentity(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name:   "envoy example with uri",
			values: []string{`By=spiffe://cluster.local/ns/default/sa/api;Hash=abc;URI=spiffe://cluster.local/ns/default/sa/client`},
			want:   "spiffe://cluster.local/ns/default/sa/client",
		},
		{
			name:   "quoted uri",
			values: []string{`Hash=deadbeef;URI="spiffe://cluster.local/ns/foo/sa/bar"`},
			want:   "spiffe://cluster.local/ns/foo/sa/bar",
		},
		{
			// The proxy appends its verified entry last (Envoy
			// APPEND_FORWARD), so the last URI is the trustworthy one.
			name:   "multiple certs comma-separated picks last URI",
			values: []string{`Hash=x;URI=spiffe://a, Hash=y;URI=spiffe://b`},
			want:   "spiffe://b",
		},
		{
			name:   "subject with embedded comma does not split entries",
			values: []string{`Subject="CN=foo,O=bar";URI=spiffe://z`},
			want:   "spiffe://z",
		},
		{
			name:   "no URI field",
			values: []string{`Hash=abc;Subject="CN=foo"`},
			want:   "",
		},
		{
			name:   "empty slice",
			values: nil,
			want:   "",
		},
		{
			name:   "case-insensitive key",
			values: []string{`uri=spiffe://case`},
			want:   "spiffe://case",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseSPIFFEIdentity(tc.values)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A caller that sets its own X-Forwarded-Client-Cert must not be able to
// choose the principal that lands in the audit log.
//
// Envoy's APPEND_FORWARD mode appends the sidecar's verified entry after
// anything the downstream already sent, so with a first-match parse any
// in-mesh service allowed by intentions could attribute its decisions to
// another service — corrupting the one record of who asked for what.
func TestParseSPIFFEIdentity_ForgedLeadingEntryIsIgnored(t *testing.T) {
	const victim = "spiffe://cluster.local/ns/default/sa/payments"
	const real = "spiffe://cluster.local/ns/default/sa/attacker"

	cases := []struct {
		name   string
		values []string
	}{
		{
			name:   "forged entry in the same header value",
			values: []string{`URI=` + victim + `,Hash=abc;URI=` + real},
		},
		{
			name:   "forged entry as a separate header value",
			values: []string{`URI=` + victim, `Hash=abc;URI=` + real},
		},
		{
			name:   "forged entry with quoting",
			values: []string{`URI="` + victim + `",Hash=abc;URI="` + real + `"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseSPIFFEIdentity(tc.values)
			if got == victim {
				t.Errorf("caller-supplied identity %q was accepted as the principal", got)
			}
			if got != real {
				t.Errorf("got %q, want the proxy-appended identity %q", got, real)
			}
		})
	}
}

// SANITIZE_SET leaves exactly one entry, so last-match must behave the same
// as before for the single-entry case every non-appending proxy produces.
func TestParseSPIFFEIdentity_SingleEntryUnchanged(t *testing.T) {
	const id = "spiffe://cluster.local/ns/default/sa/ci"
	if got := ParseSPIFFEIdentity([]string{`By=x;Hash=abc;URI=` + id + `;DNS=svc`}); got != id {
		t.Errorf("got %q, want %q", got, id)
	}
}
