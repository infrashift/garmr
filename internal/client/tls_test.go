package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infrashift/garmr/internal/tlsconf/tlstest"
)

// tlsServer starts an HTTPS test server with a certificate from ca. With
// clientCA non-nil it requires and verifies client certificates.
func tlsServer(t *testing.T, ca, clientCA *tlstest.CA) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "test"})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.Server(t, "garmr").TLSCertificate(t)}}
	if clientCA != nil {
		srv.TLS.ClientCAs = clientCA.Pool()
		srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestNewClient_PrivateCA(t *testing.T) {
	ca := tlstest.NewCA(t, "private")
	srv := tlsServer(t, ca, nil)
	caFile := ca.WriteCA(t, t.TempDir(), "ca")

	// Without the CA the private certificate is rejected.
	plain, err := NewClient(Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, healthErr := plain.Health(context.Background()); healthErr == nil {
		t.Fatal("Health succeeded against an untrusted certificate")
	}

	c, err := NewClient(Config{Address: srv.URL, CACertFile: caFile})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health with --ca-cert: %v", err)
	}
}

func TestNewClient_MutualTLS(t *testing.T) {
	ca := tlstest.NewCA(t, "private")
	clientCA := tlstest.NewCA(t, "clients")
	srv := tlsServer(t, ca, clientCA)
	dir := t.TempDir()
	caFile := ca.WriteCA(t, dir, "ca")
	certFile, keyFile := clientCA.Client(t, "ci", "spiffe://dc1/ns/default/svc/ci").Write(t, dir, "client")

	noCert, err := NewClient(Config{Address: srv.URL, CACertFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, healthErr := noCert.Health(context.Background()); healthErr == nil {
		t.Fatal("Health succeeded without the required client certificate")
	}

	c, err := NewClient(Config{Address: srv.URL, CACertFile: caFile, ClientCertFile: certFile, ClientKeyFile: keyFile})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health with a client certificate: %v", err)
	}
}

func TestNewClient_TLSOptionErrors(t *testing.T) {
	dir := t.TempDir()
	ca := tlstest.NewCA(t, "private")
	caFile := ca.WriteCA(t, dir, "ca")
	certFile, keyFile := ca.Client(t, "ci").Write(t, dir, "client")
	junk := filepath.Join(dir, "junk.pem")
	tlstest.WriteFile(t, junk, []byte("junk"))

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"tls options on http", Config{Address: "http://localhost:8080", CACertFile: caFile}, "require an https:// address"},
		{"tls options on default address", Config{ClientCertFile: certFile, ClientKeyFile: keyFile}, "require an https:// address"},
		{"cert without key", Config{Address: "https://x", ClientCertFile: certFile}, "must be set together"},
		{"key without cert", Config{Address: "https://x", ClientKeyFile: keyFile}, "must be set together"},
		{"missing CA file", Config{Address: "https://x", CACertFile: filepath.Join(dir, "nope")}, "reading CA certificate"},
		{"junk CA file", Config{Address: "https://x", CACertFile: junk}, "contains no PEM certificates"},
		{"bad key pair", Config{Address: "https://x", ClientCertFile: certFile, ClientKeyFile: junk}, "loading client certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}
