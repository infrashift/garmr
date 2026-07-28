package client

import (
	"strings"
	"testing"
)

// TestNewClient_ValidatesAddress covers the constructor's error return, which
// used to be unconditionally nil. That made `garmr health --wait` dead code:
// --wait was only consulted on a NewClient failure that could never happen.
func TestNewClient_ValidatesAddress(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		wantErr    bool
		wantErrHas string
	}{
		{name: "empty defaults to localhost", address: "", wantErr: false},
		{name: "http", address: "http://localhost:8080", wantErr: false},
		{name: "https", address: "https://garmr.example.com", wantErr: false},
		{name: "trailing slash trimmed", address: "http://localhost:8080/", wantErr: false},
		{
			name:       "missing scheme",
			address:    "localhost:8080",
			wantErr:    true,
			wantErrHas: "scheme must be http or https",
		},
		{
			name:       "wrong scheme",
			address:    "ftp://example.com",
			wantErr:    true,
			wantErrHas: "scheme must be http or https",
		},
		{
			name:       "no host",
			address:    "http://",
			wantErr:    true,
			wantErrHas: "missing host",
		},
		{
			name:       "unparseable",
			address:    "http://[::1",
			wantErr:    true,
			wantErrHas: "invalid server address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(Config{Address: tt.address})

			if tt.wantErr {
				if err == nil {
					t.Fatalf("NewClient(%q) succeeded, want an error", tt.address)
				}
				if !strings.Contains(err.Error(), tt.wantErrHas) {
					t.Errorf("error = %v, want it to contain %q", err, tt.wantErrHas)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewClient(%q) failed: %v", tt.address, err)
			}
			if strings.HasSuffix(c.baseURL, "/") {
				t.Errorf("baseURL %q has a trailing slash; request paths would double up", c.baseURL)
			}
		})
	}
}
