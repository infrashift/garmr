package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func TestNewServer_EnablesAuditAndRateLimit(t *testing.T) {
	tmp := t.TempDir()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cfg := Config{
		AuditEnabled:       true,
		AuditPath:          filepath.Join(tmp, "audit.log"),
		RateLimitEnabled:   true,
		RateLimitPerSecond: 50,
		RateLimitBurst:     100,
		Version:            "test-1.2.3",
	}

	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	if srv.auditLogger == nil {
		t.Error("expected audit logger to be initialized")
	}
	if srv.rateLimiter == nil {
		t.Error("expected rate limiter to be initialized")
	}
	if srv.obs == nil {
		t.Error("expected observability provider to be initialized")
	}
}

func TestNewServer_AuditInitFailureBubbles(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Point the audit directory at a path that collides with an existing file.
	// lumberjack's mkdir-all will fail, surfacing as a NewServer error.
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "not-a-dir")
	if err := writeFile(fake, []byte("file")); err != nil {
		t.Fatalf("pre-seed: %v", err)
	}

	cfg := Config{
		AuditEnabled: true,
		AuditPath:    filepath.Join(fake, "audit.log"), // parent is a file, not a dir
	}
	if _, err := NewServer(cfg, eng, zap.NewNop()); err == nil {
		t.Fatal("expected NewServer error when audit dir cannot be created")
	}
}

func TestNewServer_LogsStorageInitFailure(t *testing.T) {
	// With a bogus storage type, initStorageBackend fails — NewServer logs
	// a warning and still returns a working (storage-less) server.
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	srv, err := NewServer(Config{StorageType: "carrier-pigeon"}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer should tolerate storage init failure, got %v", err)
	}
	if srv.storageBackend != nil {
		t.Error("expected no storage backend after init failure")
	}
}

// TestHealthHandler_Checkers exercises the policy + storage health checkers
// registered by NewServer.
func TestHealthHandler_Checkers(t *testing.T) {
	srv := newMetricsTestServer(t)

	// policies checker should report healthy — newMetricsTestServer loads one.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp := srv.healthHandler.Check(ctx)
	if resp.Checks["policies"] == nil {
		t.Fatal("expected policies checker to be registered")
	}
	if resp.Checks["storage"] == nil {
		t.Fatal("expected storage checker to be registered")
	}
}
