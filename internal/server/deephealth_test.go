package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// /health/deep must report an honest status code: 200 only while every
// check (including the storage round trip) is healthy, 503 once the policy
// volume goes away — that round trip is the only signal a shared-volume
// deployment has that the mount is still readable.
func TestDeepHealth_StatusFollowsStorage(t *testing.T) {
	dir := t.TempDir()
	writeLifecyclePolicy(t, dir)

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPoliciesFromDir(context.Background(), dir); loadErr != nil {
		t.Fatalf("loading policies: %v", loadErr)
	}

	srv, err := NewServer(Config{PolicyDir: dir}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func() (int, string) {
		t.Helper()
		resp, getErr := http.Get(ts.URL + "/health/deep")
		if getErr != nil {
			t.Fatal(getErr)
		}
		defer resp.Body.Close()
		var body struct {
			Status string `json:"status"`
		}
		if decodeErr := json.NewDecoder(resp.Body).Decode(&body); decodeErr != nil {
			t.Fatalf("body is not JSON: %v", decodeErr)
		}
		return resp.StatusCode, body.Status
	}

	if status, health := get(); status != http.StatusOK || health != "healthy" {
		t.Fatalf("healthy volume: got %d/%q, want 200/healthy", status, health)
	}

	// The volume disappears out from under the running server: the storage
	// round trip fails, and the status code must say so.
	if rmErr := os.RemoveAll(dir); rmErr != nil {
		t.Fatal(rmErr)
	}
	if status, health := get(); status != http.StatusServiceUnavailable || health == "healthy" {
		t.Fatalf("broken volume: got %d/%q, want 503/non-healthy", status, health)
	}
}

// The auth split is deliberate: probes can't carry credentials, so
// /healthz//readyz//livez are exempt, while /health/deep performs storage
// I/O on every call and stays behind the API key.
func TestDeepHealth_RequiresAPIKeyUnlikeProbes(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret"})
	defer ts.Close()

	for _, path := range []string{"/healthz", "/readyz", "/livez"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("probe %s must be auth-exempt, got 401", path)
		}
	}

	resp, err := http.Get(ts.URL + "/health/deep")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/health/deep without a key: got %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health/deep", nil)
	req.Header.Set("X-API-Key", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("/health/deep with the key: still 401")
	}
}
