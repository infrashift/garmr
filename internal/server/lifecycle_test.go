package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// writeLifecyclePolicy writes one valid policy in the on-disk (package +
// named document) format into dir.
func writeLifecyclePolicy(t *testing.T, dir string) {
	t.Helper()
	const src = `package policy

lifecycle_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "lifecycle-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "LC-001"
			description: "always satisfiable"
			severity:    "low"
			expr: {match: {path: "env", exists: false}}
		}]
		enforcement: action: "deny"
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(src), 0644); err != nil {
		t.Fatalf("writing lifecycle policy: %v", err)
	}
}

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
	// Startup fails closed on a policy dir with zero policies, so the
	// lifecycle test needs a real one on disk.
	writeLifecyclePolicy(t, tmpDir)
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
