package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// fleetServer stands in for a mesh upstream: each reload is answered by a
// different instance, round-robin, exactly as Envoy would.
func fleetServer(t *testing.T, instances int, digest string) *httptest.Server {
	t.Helper()
	var n atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := fmt.Sprintf("alloc-%d", n.Add(1)%int64(instances))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":         true,
			"policies_loaded": 3,
			"digest":          digest,
			"reload_time_ms":  1,
			"storage_type":    "filesystem",
			"instance_id":     id,
		})
	}))
}

// Convergence through a load-balancing upstream must be judged on the set of
// instances actually observed, not on a single successful call.
func TestConverge_SucceedsOnlyAfterEveryInstanceAcknowledges(t *testing.T) {
	const digest = "abc123"
	ts := fleetServer(t, 3, digest)
	defer ts.Close()

	exit := stubExit(t)
	captureOutput(t, func() {
		_ = runPolicyReloadConverge(ts.URL, digest, 3, 10*time.Second)
	})

	if exit.Called {
		t.Errorf("converge exited %d despite reaching every instance", exit.Code)
	}
}

// The failure this whole mode exists to prevent: fewer instances answer than
// the fleet has, so some are still serving the old policy set. A single
// success must not be reported as convergence.
func TestConverge_FailsWhenAnInstanceIsNeverReached(t *testing.T) {
	const digest = "abc123"
	ts := fleetServer(t, 1, digest) // only ever one instance answers
	defer ts.Close()

	exit := stubExit(t)
	captureOutput(t, func() {
		_ = runPolicyReloadConverge(ts.URL, digest, 3, 1500*time.Millisecond)
	})

	if !exit.Called {
		t.Fatal("converge reported success while 2 of 3 instances were never reached")
	}
	if exit.Code != 1 {
		t.Errorf("exit code = %d, want 1", exit.Code)
	}
}

// A digest mismatch is a failure even when every instance answers: the fleet
// converged on content that is not what CI shipped.
func TestConverge_FailsOnDigestMismatch(t *testing.T) {
	ts := fleetServer(t, 2, "actual-digest")
	defer ts.Close()

	exit := stubExit(t)
	captureOutput(t, func() {
		_ = runPolicyReloadConverge(ts.URL, "expected-digest", 2, 5*time.Second)
	})

	if !exit.Called {
		t.Error("converge succeeded despite the reported digest differing from --expect-digest")
	}
}

// Without instance_id there is no way to distinguish two instances from one
// answering twice, so the command must refuse rather than guess.
func TestConverge_FailsWhenServerOmitsInstanceID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":         true,
			"policies_loaded": 3,
			"digest":          "abc123",
			"reload_time_ms":  1,
			"storage_type":    "filesystem",
		})
	}))
	defer ts.Close()

	exit := stubExit(t)
	captureOutput(t, func() {
		_ = runPolicyReloadConverge(ts.URL, "abc123", 2, 3*time.Second)
	})

	if !exit.Called {
		t.Error("converge claimed success against a server that cannot identify its instances")
	}
}

// Instances disagreeing is a split fleet even if the count is satisfied.
func TestConverge_FailsWhenInstancesDiverge(t *testing.T) {
	var n atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		digest := "digest-a"
		if i%2 == 0 {
			digest = "digest-b"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":         true,
			"policies_loaded": 3,
			"digest":          digest,
			"reload_time_ms":  1,
			"storage_type":    "filesystem",
			"instance_id":     fmt.Sprintf("alloc-%d", i%2),
		})
	}))
	defer ts.Close()

	exit := stubExit(t)
	captureOutput(t, func() {
		_ = runPolicyReloadConverge(ts.URL, "", 2, 5*time.Second)
	})

	if !exit.Called {
		t.Error("converge succeeded while instances reported different digests")
	}
}

// The JSON report has to name the instances, so a failed CI run says which
// instances were reached rather than only that something went wrong.
func TestConverge_JSONReportNamesInstances(t *testing.T) {
	const digest = "abc123"
	ts := fleetServer(t, 2, digest)
	defer ts.Close()

	viper.Set("output", "json")
	defer viper.Set("output", "")

	exit := stubExit(t)
	out, _ := captureOutput(t, func() {
		_ = runPolicyReloadConverge(ts.URL, digest, 2, 10*time.Second)
	})
	if exit.Called {
		t.Fatalf("unexpected exit %d", exit.Code)
	}

	var report convergeReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("report is not JSON: %v (%q)", err, out)
	}
	if !report.Converged {
		t.Error("report says not converged")
	}
	if len(report.Seen) != 2 {
		t.Errorf("instances_seen = %v, want 2 entries", report.Seen)
	}
	if report.Digest != digest {
		t.Errorf("digest = %q, want %q", report.Digest, digest)
	}
}

// --converge is only meaningful with a target instance count and a single
// load-balancing address. Guessing either would let the command report
// convergence it never verified, which is the failure the mode exists to
// prevent — so these are refused up front rather than defaulted.
func TestRunPolicyReload_ConvergeFlagGuards(t *testing.T) {
	tests := []struct {
		name    string
		flags   []flagSpec
		wantErr string
	}{
		{
			name: "converge without instances",
			flags: []flagSpec{
				{Kind: "bool", Name: "converge", Value: true},
				{Kind: "int", Name: "instances", Value: 0},
			},
			wantErr: "--instances",
		},
		{
			name: "converge with multiple servers",
			flags: []flagSpec{
				{Kind: "bool", Name: "converge", Value: true},
				{Kind: "int", Name: "instances", Value: 2},
				{Kind: "stringSlice", Name: "servers", Value: []string{"http://a:8080", "http://b:8080"}},
			},
			wantErr: "single address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := append([]flagSpec{
				{Kind: "string", Name: "expect-digest", Value: ""},
				{Kind: "duration", Name: "converge-timeout", Value: time.Minute},
			}, tt.flags...)

			err := runPolicyReload(newTestCmd(t, flags...), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
