// cmd/garmr/commands_test.go
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/infrashift/garmr/internal/client"
)

type clientCfg = client.Config

func healthFlagSet(t *testing.T) *cobraCmd {
	t.Helper()
	return newTestCmd(t,
		flagSpec{Kind: "bool", Name: "wait"},
		flagSpec{Kind: "duration", Name: "timeout", Value: 30 * time.Second},
	)
}

func TestRunHealth_Healthy(t *testing.T) {
	newTestServer(t)
	cmd := healthFlagSet(t)

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runHealth(cmd, nil); err != nil {
			t.Fatalf("runHealth: %v", err)
		}
	})
	if !strings.Contains(stdout, "healthy") {
		t.Errorf("expected healthy, got %q", stdout)
	}
}

func TestRunHealth_JSONOutput(t *testing.T) {
	newTestServer(t)
	viperSetOutput(t, "json")
	cmd := healthFlagSet(t)

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runHealth(cmd, nil)
	})
	if !strings.Contains(stdout, `"healthy"`) {
		t.Errorf("expected JSON health, got %q", stdout)
	}
}

func TestRunHealth_Unreachable(t *testing.T) {
	// No server started, but set server URL to an unreachable port.
	newTestServer(t)
	viperSetServer(t, "http://127.0.0.1:1")

	cmd := healthFlagSet(t)
	rec := stubExit(t)
	_, _ = captureOutput(t, func() {
		_ = runHealth(cmd, nil)
	})
	if rec.Code != 1 {
		t.Errorf("expected exit 1 on unreachable, got %d", rec.Code)
	}
}

func TestRunHealth_WaitSucceeds(t *testing.T) {
	newTestServer(t)
	cmd := healthFlagSet(t)
	cmd.Flags().Set("wait", "true")
	cmd.Flags().Set("timeout", "5s")

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runHealth(cmd, nil); err != nil {
			t.Fatalf("runHealth wait: %v", err)
		}
	})
	if !strings.Contains(stdout, "healthy") {
		t.Errorf("expected healthy with wait, got %q", stdout)
	}
}

func TestVersionCmd_Table(t *testing.T) {
	viperSetOutput(t, "table")
	stdout, _ := captureOutput(t, func() {
		versionCmd.Run(versionCmd, nil)
	})
	if !strings.Contains(stdout, "Garmr CLI") {
		t.Errorf("expected version header, got %q", stdout)
	}
}

func TestVersionCmd_JSON(t *testing.T) {
	viperSetOutput(t, "json")
	stdout, _ := captureOutput(t, func() {
		versionCmd.Run(versionCmd, nil)
	})
	if !strings.Contains(stdout, `"version"`) {
		t.Errorf("expected JSON version, got %q", stdout)
	}
}

// --- waitForHealth (exercised directly) ---

func TestWaitForHealth_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	err := waitForHealth(ctx, clientCfg{Address: "http://127.0.0.1:1"})
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestWaitForHealth_EventuallyHealthy(t *testing.T) {
	env := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = captureOutput(t, func() {
		if err := waitForHealth(ctx, clientCfg{Address: env.URL}); err != nil {
			t.Fatalf("waitForHealth: %v", err)
		}
	})
}

// --- removed stub commands stay removed ---

func TestDataCommandRemoved(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "data" {
			t.Error("stub 'data' command should not be registered")
		}
	}
}

// The exit code must not depend on the output format: an unhealthy server
// reported with -o json used to exit 0.
func TestRunHealth_UnhealthyExitsNonzeroInEveryFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy": false, "version": "test"}`))
	}))
	t.Cleanup(srv.Close)
	viperSetServer(t, srv.URL)

	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			viperSetOutput(t, format)
			rec := stubExit(t)
			_, _ = captureOutput(t, func() {
				_ = runHealth(healthFlagSet(t), nil)
			})
			if rec.Code != exitNegative {
				t.Errorf("-o %s: exit = %d, want %d", format, rec.Code, exitNegative)
			}
		})
	}
}
