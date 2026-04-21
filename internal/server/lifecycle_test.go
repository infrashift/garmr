package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// freePort returns an ephemeral TCP port likely free on the loopback interface.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// TestServer_StartStopLifecycle exercises Start → ready probe → Stop via
// context cancellation. This covers Start, startHTTP, and Stop in one go.
func TestServer_StartStopLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cfg := Config{
		HTTPAddr:  addr,
		PolicyDir: tmpDir, // triggers initStorageBackend filesystem branch
	}
	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	// Wait for readiness (up to ~2s).
	deadline := time.Now().Add(2 * time.Second)
	var ready bool
	client := &http.Client{Timeout: 200 * time.Millisecond}
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-errCh
		t.Fatal("server did not become ready")
	}

	// Trigger shutdown.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error on cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down within 3s")
	}
}
