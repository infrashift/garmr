package tlsconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infrashift/garmr/internal/tlsconf/tlstest"
)

type material struct {
	dir, cert, key, ca string
	srvCA              *tlstest.CA
	clientCA           *tlstest.CA
}

func newMaterial(t *testing.T) material {
	t.Helper()
	dir := t.TempDir()
	srvCA := tlstest.NewCA(t, "server-ca")
	clientCA := tlstest.NewCA(t, "client-ca")
	cert, key := srvCA.Server(t, "garmr-1").Write(t, dir, "server")
	return material{
		dir: dir, cert: cert, key: key,
		ca:    clientCA.WriteCA(t, dir, "client-ca"),
		srvCA: srvCA, clientCA: clientCA,
	}
}

// bumpMtime forces a distinct stamp: coarse filesystems can give a rewrite
// within the same tick the same mtime.
func bumpMtime(t *testing.T, path string, d time.Duration) {
	t.Helper()
	ts := time.Now().Add(d)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func handshakeLeaf(t *testing.T, r *Reloader) *x509.Certificate {
	t.Helper()
	cfg, err := r.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Certificates[0].Leaf
}

func TestNew_ServerOnly(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.MutualTLS() {
		t.Error("MutualTLS() = true without a client CA")
	}
	cfg, _ := r.TLSConfig().GetConfigForClient(nil)
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if got := strings.Join(cfg.NextProtos, ","); got != "h2,http/1.1" {
		t.Errorf("NextProtos = %q", got)
	}
	if r.Leaf().Subject.CommonName != "garmr-1" {
		t.Errorf("Leaf CN = %q", r.Leaf().Subject.CommonName)
	}
	if r.opts.ReloadInterval != DefaultReloadInterval {
		t.Errorf("ReloadInterval = %v, want default", r.opts.ReloadInterval)
	}
}

func TestNew_MutualTLS(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key, ClientCAFile: m.ca, MinVersion: "1.3"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !r.MutualTLS() {
		t.Error("MutualTLS() = false with a client CA")
	}
	cfg, _ := r.TLSConfig().GetConfigForClient(nil)
	// IfGiven, not Require: probes present no client certificate.
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs not set")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
}

// A single PEM holding certificate, chain and key works for both paths. This is
// the recommended Nomad recipe: one template renders one file atomically,
// so a renewal can never be observed half written.
func TestNew_CombinedPEM(t *testing.T) {
	m := newMaterial(t)
	pair := m.srvCA.Server(t, "combined")
	combined := filepath.Join(m.dir, "garmr.pem")
	tlstest.WriteFile(t, combined, append(append(append([]byte{}, pair.CertPEM...), m.srvCA.PEM...), pair.KeyPEM...))

	r, err := New(Options{CertFile: combined, KeyFile: combined}, nil)
	if err != nil {
		t.Fatalf("New with a combined PEM: %v", err)
	}
	cfg, _ := r.TLSConfig().GetConfigForClient(nil)
	if n := len(cfg.Certificates[0].Certificate); n != 2 {
		t.Errorf("chain length = %d, want leaf + CA", n)
	}
	if r.Leaf().Subject.CommonName != "combined" {
		t.Errorf("leaf CN = %q", r.Leaf().Subject.CommonName)
	}
}

func TestNew_Errors(t *testing.T) {
	m := newMaterial(t)
	empty := filepath.Join(m.dir, "empty.pem")
	tlstest.WriteFile(t, empty, []byte("not a pem"))
	other := tlstest.NewCA(t, "other").Server(t, "x")
	_, otherKey := other.Write(t, m.dir, "other")

	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"no cert", Options{KeyFile: m.key}, "both required"},
		{"no key", Options{CertFile: m.cert}, "both required"},
		{"bad version", Options{CertFile: m.cert, KeyFile: m.key, MinVersion: "1.1"}, "invalid TLS min version"},
		{"missing file", Options{CertFile: filepath.Join(m.dir, "nope"), KeyFile: m.key}, "reading TLS files"},
		{"mismatched pair", Options{CertFile: m.cert, KeyFile: otherKey}, "loading TLS key pair"},
		{"empty CA", Options{CertFile: m.cert, KeyFile: m.key, ClientCAFile: empty}, "contains no PEM certificates"},
		{"missing CA", Options{CertFile: m.cert, KeyFile: m.key, ClientCAFile: filepath.Join(m.dir, "nope")}, "reading TLS files"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestReload_SwapsOnChange(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Reload() {
		t.Fatal("Reload() swapped with no file change")
	}

	m.srvCA.Server(t, "garmr-2").Write(t, m.dir, "server")
	bumpMtime(t, m.cert, time.Second)
	bumpMtime(t, m.key, time.Second)

	if !r.Reload() {
		t.Fatal("Reload() did not swap after rotation")
	}
	if cn := handshakeLeaf(t, r).Subject.CommonName; cn != "garmr-2" {
		t.Errorf("served CN = %q, want garmr-2", cn)
	}
}

func TestReload_HalfWrittenRotationKeepsOldCert(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := m.srvCA.Server(t, "garmr-2")

	// The renderer has written the new certificate but not yet its key.
	tlstest.WriteFile(t, m.cert, next.CertPEM)
	bumpMtime(t, m.cert, time.Second)
	if r.Reload() {
		t.Fatal("Reload() swapped in a mismatched pair")
	}
	if cn := handshakeLeaf(t, r).Subject.CommonName; cn != "garmr-1" {
		t.Errorf("served CN = %q, want the previous garmr-1", cn)
	}
	// The same broken state is not retried (or re-logged) every tick.
	if r.Reload() {
		t.Fatal("Reload() swapped on an unchanged broken state")
	}

	// Then the key lands.
	tlstest.WriteFile(t, m.key, next.KeyPEM)
	bumpMtime(t, m.key, 2*time.Second)
	if !r.Reload() {
		t.Fatal("Reload() did not recover once the key arrived")
	}
	if cn := handshakeLeaf(t, r).Subject.CommonName; cn != "garmr-2" {
		t.Errorf("served CN = %q, want garmr-2", cn)
	}
}

func TestReload_MissingFileKeepsOldCert(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.key); err != nil {
		t.Fatal(err)
	}
	if r.Reload() {
		t.Fatal("Reload() swapped with the key missing")
	}
	if handshakeLeaf(t, r) == nil {
		t.Fatal("no certificate served after a failed reload")
	}
}

func TestReload_RotatesClientCA(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key, ClientCAFile: m.ca}, nil)
	if err != nil {
		t.Fatal(err)
	}
	newCA := tlstest.NewCA(t, "client-ca-2")
	tlstest.WriteFile(t, m.ca, newCA.PEM)
	bumpMtime(t, m.ca, time.Second)
	if !r.Reload() {
		t.Fatal("Reload() did not pick up the new client CA")
	}
	cfg, _ := r.TLSConfig().GetConfigForClient(nil)
	leaf := newCA.Client(t, "svc").Cert
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("cert from rotated CA does not verify: %v", err)
	}
}

func TestRun_PollsUntilCancelled(t *testing.T) {
	m := newMaterial(t)
	r, err := New(Options{CertFile: m.cert, KeyFile: m.key, ReloadInterval: 10 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	m.srvCA.Server(t, "garmr-2").Write(t, m.dir, "server")
	bumpMtime(t, m.cert, time.Second)
	bumpMtime(t, m.key, time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for r.Leaf().Subject.CommonName != "garmr-2" {
		if time.Now().After(deadline) {
			t.Fatal("Run never picked up the rotated certificate")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPeerIdentity(t *testing.T) {
	spiffe := mustURL(t, "spiffe://dc1/ns/default/svc/web")
	other := mustURL(t, "urn:example:web")
	chain := func(uris ...*url.URL) *tls.ConnectionState {
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: uris}}}}
	}
	cases := []struct {
		name string
		cs   *tls.ConnectionState
		want string
	}{
		{"nil", nil, ""},
		{"plaintext-equivalent", &tls.ConnectionState{}, ""},
		{"unverified cert ignored", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{spiffe}}}}, ""},
		{"empty chain", &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, ""},
		{"spiffe preferred", chain(other, spiffe), spiffe.String()},
		{"first URI fallback", chain(other), other.String()},
		{"no URIs", chain(), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PeerIdentity(tc.cs); got != tc.want {
				t.Errorf("PeerIdentity = %q, want %q", got, tc.want)
			}
		})
	}
	if HasVerifiedPeer(nil) || HasVerifiedPeer(&tls.ConnectionState{}) || !HasVerifiedPeer(chain()) {
		t.Error("HasVerifiedPeer wrong")
	}
}
