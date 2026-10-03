package server

import (
	"encoding/json"
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
