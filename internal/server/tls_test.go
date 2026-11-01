package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/tlsconf"
	"github.com/infrashift/garmr/internal/tlsconf/tlstest"
)

type tlsMaterial struct {
	srvCA, clientCA *tlstest.CA
	opts            tlsconf.Options
}

// newTLSMaterial writes a server certificate and, with mutual, a client CA.
func newTLSMaterial(t *testing.T, mutual bool) tlsMaterial {
	t.Helper()
	dir := t.TempDir()
	m := tlsMaterial{srvCA: tlstest.NewCA(t, "server-ca"), clientCA: tlstest.NewCA(t, "client-ca")}
	m.opts.CertFile, m.opts.KeyFile = m.srvCA.Server(t, "garmr").Write(t, dir, "server")
	if mutual {
		m.opts.ClientCAFile = m.clientCA.WriteCA(t, dir, "client-ca")
	}
	return m
}

// syncBuffer is a goroutine-safe audit sink: handlers write while the test
// reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startTLSServer runs a real Start() listener with TLS, so the handshake,
// ALPN and the reloader goroutine are all exercised.
func startTLSServer(t *testing.T, m tlsMaterial, mutate func(*Config)) (string, *syncBuffer) {
	t.Helper()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeLifecyclePolicy(t, dir)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := Config{HTTPAddr: addr, PolicyDir: dir, TLSEnabled: true, TLS: m.opts}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	audit := &syncBuffer{}
	srv.auditLogger = slog.New(slog.NewJSONHandler(audit, nil))

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("Start: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	base := "https://" + addr
	probe := httpsClient(m, nil)
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := probe.Get(base + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base, audit
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS server never became ready (last err %v)", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func httpsClient(m tlsMaterial, clientCert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: m.srvCA.Pool()}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true},
	}
}

// evalResult is what the tests need from a response, so no body escapes
// the helper unclosed.
type evalResult struct {
	StatusCode int
	Proto      string
}

func evaluate(t *testing.T, c *http.Client, base string, header http.Header) (evalResult, error) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"input": map[string]any{"env": "prod"}})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return evalResult{}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return evalResult{StatusCode: resp.StatusCode, Proto: resp.Proto}, nil
}

func TestTLS_ServesHTTPSWithHTTP2(t *testing.T) {
	m := newTLSMaterial(t, false)
	base, _ := startTLSServer(t, m, nil)

	resp, err := evaluate(t, httpsClient(m, nil), base, nil)
	if err != nil {
		t.Fatalf("evaluate over TLS: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (no client cert needed without mTLS)", resp.StatusCode)
	}
	// GetConfigForClient replaces the server's TLS config, so ALPN has to
	// be restated in the snapshot or HTTP/2 silently disappears.
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("proto = %s, want HTTP/2.0", resp.Proto)
	}

	// Plain HTTP against the TLS listener does not get an answer.
	if plain, err := http.Get(strings.Replace(base, "https://", "http://", 1) + "/readyz"); err == nil {
		plain.Body.Close()
		if plain.StatusCode == http.StatusOK {
			t.Error("plaintext request served by the TLS listener")
		}
	}
}

func TestTLS_MutualTLS(t *testing.T) {
	m := newTLSMaterial(t, true)
	base, audit := startTLSServer(t, m, nil)
	const id = "spiffe://dc1/ns/default/svc/web"
	cert := m.clientCA.Client(t, "web", id).TLSCertificate(t)

	t.Run("probe without client cert is served", func(t *testing.T) {
		resp, err := httpsClient(m, nil).Get(base + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/readyz = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("API without client cert is 401", func(t *testing.T) {
		resp, err := evaluate(t, httpsClient(m, nil), base, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("verified cert is the principal and XFCC is ignored", func(t *testing.T) {
		forged := http.Header{"X-Forwarded-Client-Cert": {`URI=spiffe://dc1/ns/default/svc/forged`}}
		resp, err := evaluate(t, httpsClient(m, &cert), base, forged)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		got := audit.String()
		if !strings.Contains(got, `"principal":"`+id+`"`) {
			t.Errorf("audit missing certificate principal:\n%s", got)
		}
		if strings.Contains(got, "forged") {
			t.Errorf("audit used the forgeable XFCC header:\n%s", got)
		}
	})

	t.Run("cert from another CA fails the handshake", func(t *testing.T) {
		rogue := tlstest.NewCA(t, "rogue").Client(t, "web", id).TLSCertificate(t)
		// A Go client only offers a certificate whose issuer the server
		// lists as acceptable, so a static Certificates slice would quietly
		// send nothing. Force the rogue certificate onto the wire.
		c := httpsClient(m, nil)
		c.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate =
			func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &rogue, nil }
		if resp, err := evaluate(t, c, base, nil); err == nil {
			t.Errorf("untrusted client certificate accepted (status %d), want a handshake failure", resp.StatusCode)
		}
	})
}

func TestTLS_MutualTLSAndAPIKeyBothRequired(t *testing.T) {
	m := newTLSMaterial(t, true)
	base, _ := startTLSServer(t, m, func(c *Config) { c.APIKey = "s3cret" })
	cert := m.clientCA.Client(t, "web", "spiffe://dc1/svc/web").TLSCertificate(t)

	resp, err := evaluate(t, httpsClient(m, &cert), base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("cert without key: status = %d, want 401", resp.StatusCode)
	}
	resp, err = evaluate(t, httpsClient(m, nil), base, http.Header{"X-Api-Key": {"s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("key without cert: status = %d, want 401", resp.StatusCode)
	}
	resp, err = evaluate(t, httpsClient(m, &cert), base, http.Header{"X-Api-Key": {"s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cert and key: status = %d, want 200", resp.StatusCode)
	}
}

func TestNewServer_TLSValidation(t *testing.T) {
	newEng := func(t *testing.T) *engine.Engine {
		eng, err := engine.NewEngine(zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		return eng
	}
	serverOnly := newTLSMaterial(t, false)
	mutual := newTLSMaterial(t, true)

	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"enabled without files", Config{TLSEnabled: true}, "configuring TLS"},
		{"bad min version", Config{TLSEnabled: true, TLS: tlsconf.Options{
			CertFile: serverOnly.opts.CertFile, KeyFile: serverOnly.opts.KeyFile, MinVersion: "1.0"}}, "invalid TLS min version"},
		{"identity limiter needs mTLS", Config{TLSEnabled: true, TLS: serverOnly.opts,
			RateLimitEnabled: true, RateLimitClientIdentifier: "identity"}, `requires mTLS`},
		{"identity limiter with mTLS", Config{TLSEnabled: true, TLS: mutual.opts,
			RateLimitEnabled: true, RateLimitClientIdentifier: "identity"}, ""},
		{"custom identity header warns only", Config{TLSEnabled: true, TLS: serverOnly.opts, IdentityHeader: "X-Mesh-Id"}, ""},
		{"files set but disabled warns only", Config{TLS: serverOnly.opts}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer(tc.cfg, newEng(t), zap.NewNop())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewServer: %v", err)
				}
				_ = s.Stop()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestIdentityMiddleware_TLSIgnoresHeader(t *testing.T) {
	m := newTLSMaterial(t, true)
	reloader, err := tlsconf.New(m.opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{logger: zap.NewNop(), tls: reloader}

	var captured string
	h := s.identityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = PrincipalFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Client-Cert", `URI=spiffe://forged`)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if captured != "" {
		t.Errorf("principal = %q, want empty: XFCC must be ignored under TLS", captured)
	}
}
