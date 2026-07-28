package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// /readyz must reflect the server's ready state: 503 before Start, 200 while
// serving, and 503 again the moment Stop() begins draining — that flip is
// what tells the mesh to pull the instance before its listener closes.
func TestReadyz_FollowsServerLifecycle(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func() int {
		t.Helper()
		resp, err := http.Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("before ready: /readyz = %d, want 503", got)
	}

	srv.MarkReady()
	if got := get(); got != http.StatusOK {
		t.Errorf("while serving: /readyz = %d, want 200", got)
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("during shutdown: /readyz = %d, want 503", got)
	}
}
