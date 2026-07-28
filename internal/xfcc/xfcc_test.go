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
			name:   "multiple certs comma-separated picks first URI",
			values: []string{`Hash=x;URI=spiffe://a, Hash=y;URI=spiffe://b`},
			want:   "spiffe://a",
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
