package server

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// The HTTP server timeouts were hardcoded; they are config now, with the old
// values as defaults so an empty Config changes nothing.
func TestNewHTTPServer_TimeoutConfig(t *testing.T) {
	newSrv := func(cfg Config) *Server {
		t.Helper()
		eng, err := engine.NewEngine(zap.NewNop())
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		srv, err := NewServer(cfg, eng, zap.NewNop())
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		return srv
	}

	hs := newSrv(Config{}).newHTTPServer()
	if hs.ReadTimeout != 30*time.Second || hs.WriteTimeout != 60*time.Second || hs.IdleTimeout != 120*time.Second {
		t.Errorf("defaults = read %v / write %v / idle %v, want 30s/60s/120s",
			hs.ReadTimeout, hs.WriteTimeout, hs.IdleTimeout)
	}

	hs = newSrv(Config{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 6 * time.Second,
		IdleTimeout:  7 * time.Second,
	}).newHTTPServer()
	if hs.ReadTimeout != 5*time.Second || hs.WriteTimeout != 6*time.Second || hs.IdleTimeout != 7*time.Second {
		t.Errorf("overrides = read %v / write %v / idle %v, want 5s/6s/7s",
			hs.ReadTimeout, hs.WriteTimeout, hs.IdleTimeout)
	}
}
