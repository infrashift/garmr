// cmd/garmr/tls_test.go
package main

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/server"
	"github.com/infrashift/garmr/internal/tlsconf/tlstest"
)

type cliTLS struct {
	URL                       string
	caFile, certFile, keyFile string
}

// newMTLSTestServer serves the real handler over HTTPS, requiring a client
// certificate, and points viper's server at it. TLS flags are left unset.
func newMTLSTestServer(t *testing.T, cfg server.Config) cliTLS {
	t.Helper()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "pass-policy", "default", testPassPolicy); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}
	srv, err := server.NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()

	dir := t.TempDir()
	srvCA := tlstest.NewCA(t, "server-ca")
	clientCA := tlstest.NewCA(t, "client-ca")
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvCA.Server(t, "garmr").TLSCertificate(t)},
		ClientCAs:    clientCA.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	out := cliTLS{URL: ts.URL, caFile: srvCA.WriteCA(t, dir, "ca")}
	out.certFile, out.keyFile = clientCA.Client(t, "ci", "spiffe://dc1/svc/ci").Write(t, dir, "client")

	viper.Reset()
	viper.Set("server", ts.URL)
	viper.Set("output", "table")
	return out
}

func (c cliTLS) setFlags() {
	viper.Set("tls.ca_cert", c.caFile)
	viper.Set("tls.client_cert", c.certFile)
	viper.Set("tls.client_key", c.keyFile)
}

func TestClientConfig_CarriesTLSOptions(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("tls.ca_cert", "/ca.pem")
	viper.Set("tls.client_cert", "/c.pem")
	viper.Set("tls.client_key", "/c.key")

	got := clientConfig("https://garmr:8080")
	if got.Address != "https://garmr:8080" || got.CACertFile != "/ca.pem" ||
		got.ClientCertFile != "/c.pem" || got.ClientKeyFile != "/c.key" {
		t.Errorf("clientConfig = %+v", got)
	}
}

func TestInitConfig_TLSEnvVars(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Setenv("GARMR_TLS_CA_CERT", "/env/ca.pem")
	t.Setenv("GARMR_TLS_CLIENT_CERT", "/env/c.pem")
	t.Setenv("GARMR_CONFIG", "/nonexistent/garmr.yaml")
	prev := cfgFile
	cfgFile = ""
	t.Cleanup(func() { cfgFile = prev })

	initConfig()
	if got := viper.GetString("tls.ca_cert"); got != "/env/ca.pem" {
		t.Errorf("tls.ca_cert = %q, want it from GARMR_TLS_CA_CERT", got)
	}
	if got := viper.GetString("tls.client_cert"); got != "/env/c.pem" {
		t.Errorf("tls.client_cert = %q, want it from GARMR_TLS_CLIENT_CERT", got)
	}
}

func TestRunHealth_MutualTLS(t *testing.T) {
	env := newMTLSTestServer(t, server.Config{})

	t.Run("without TLS flags the handshake fails", func(t *testing.T) {
		rec := stubExit(t)
		_, _ = captureOutput(t, func() { _ = runHealth(healthFlagSet(t), nil) })
		if rec.Code != exitNegative {
			t.Errorf("exit = %d, want %d", rec.Code, exitNegative)
		}
	})

	t.Run("with --ca-cert and client cert it is healthy", func(t *testing.T) {
		env.setFlags()
		stubExit(t)
		stdout, _ := captureOutput(t, func() {
			if err := runHealth(healthFlagSet(t), nil); err != nil {
				t.Fatalf("runHealth: %v", err)
			}
		})
		if !strings.Contains(stdout, "healthy") {
			t.Errorf("stdout = %q, want healthy", stdout)
		}
	})

	t.Run("TLS flags on an http address are a config error", func(t *testing.T) {
		viper.Set("server", "http://127.0.0.1:1")
		rec := stubExit(t)
		stdout, _ := captureOutput(t, func() { _ = runHealth(healthFlagSet(t), nil) })
		if rec.Code != exitError || !strings.Contains(stdout, "https://") {
			t.Errorf("exit = %d, stdout = %q; want %d and an https hint", rec.Code, stdout, exitError)
		}
	})
}

func TestReloadInstance_MutualTLS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cue"), []byte(testDirPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	env := newMTLSTestServer(t, server.Config{PolicyDir: dir})
	env.setFlags()

	out := reloadInstance(env.URL, "")
	if out.Error != "" {
		t.Fatalf("reload over mTLS: %s", out.Error)
	}
}

// A certificate failure cannot be fixed by waiting, so --wait must report it
// at once instead of retrying silently until the timeout.
func TestWaitForHealth_TLSFailureIsImmediate(t *testing.T) {
	env := newMTLSTestServer(t, server.Config{})
	cases := []struct {
		name string
		cfg  clientCfg
	}{
		{"untrusted server certificate", clientCfg{Address: env.URL, ClientCertFile: env.certFile, ClientKeyFile: env.keyFile}},
		{"client certificate rejected", clientCfg{Address: env.URL, CACertFile: env.caFile}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			err := waitForHealth(ctx, mustClient(t, tc.cfg))
			if err == nil || !strings.Contains(err.Error(), "health check failed") {
				t.Fatalf("err = %v, want an immediate TLS failure", err)
			}
			if elapsed := time.Since(start); elapsed > 10*time.Second {
				t.Errorf("took %v; a TLS failure should not wait for the timeout", elapsed)
			}
		})
	}
}
