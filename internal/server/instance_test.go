package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// Behind a mesh upstream the caller cannot address instances individually, so
// the response has to say which instance answered. Without it a CI job that
// reloads through the upstream sees one success and concludes the fleet
// converged, while the instances it never reached serve the old policy set.
func TestPolicies_ReportsInstanceID(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/policies")
	if err != nil {
		t.Fatalf("GET /v1/policies: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	id, _ := body["instance_id"].(string)
	if id == "" {
		t.Error("GET /v1/policies omitted instance_id; convergence cannot be verified behind a load balancer")
	}
	if id != InstanceID() {
		t.Errorf("instance_id = %q, want %q", id, InstanceID())
	}
	if body["digest"] == "" {
		t.Error("GET /v1/policies omitted digest")
	}
}

// The identifier must be stable for the life of the process: a value that
// changed per request would make every reload look like a new instance and
// convergence would never terminate.
func TestInstanceID_IsStableAndNonEmpty(t *testing.T) {
	first := InstanceID()
	if first == "" {
		t.Fatal("InstanceID() is empty")
	}
	for i := 0; i < 3; i++ {
		if got := InstanceID(); got != first {
			t.Fatalf("InstanceID() changed between calls: %q then %q", first, got)
		}
	}
}

func TestResolveInstanceID(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	host := func(h string, err error) func() (string, error) {
		return func() (string, error) { return h, err }
	}

	cases := []struct {
		name     string
		vars     map[string]string
		hostname func() (string, error)
		want     string
	}{
		{"nomad alloc id wins", map[string]string{"NOMAD_ALLOC_ID": "alloc-1", "HOSTNAME": "h"}, host("h", nil), "alloc-1"},
		{"short alloc id", map[string]string{"NOMAD_SHORT_ALLOC_ID": "a1"}, host("h", nil), "a1"},
		{"HOSTNAME env is qualified by pid", map[string]string{"HOSTNAME": "web"}, host("other", nil), "web:42"},
		{"os hostname is qualified by pid", nil, host("laptop", nil), "laptop:42"},
	}
	for _, tc := range cases {
		if got := resolveInstanceID(env(tc.vars), tc.hostname, 42); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	// Two processes on one host must not share an identity, or --converge
	// would count them as one instance.
	a := resolveInstanceID(env(nil), host("laptop", nil), 100)
	b := resolveInstanceID(env(nil), host("laptop", nil), 101)
	if a == b {
		t.Errorf("two processes on one host share instance ID %q", a)
	}

	if got := resolveInstanceID(env(nil), host("", errors.New("no hostname")), 42); got == "" {
		t.Error("fallback instance ID is empty")
	}
}
