package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// TestHandleEvaluate_ResponseIncludesSummary is the end-to-end check that the
// serialised body actually reaches a client.
func TestHandleEvaluate_ResponseIncludesSummary(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "dev"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	for _, key := range []string{"summary", "evaluation_mode", "terminated_early"} {
		if _, present := body[key]; !present {
			t.Errorf("response body is missing %q", key)
		}
	}
}

// TestHandleEvaluate_NoTraceField pins the removal of the --trace surface,
// which was plumbed end to end and always returned an empty array.
func TestHandleEvaluate_NoTraceField(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "dev"},
		"trace": true,
	})
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if _, present := body["trace"]; present {
		t.Error("response still carries a trace field")
	}
}

// TestOpenAPISpec_MatchesResponseShape guards the embedded spec against
// drifting from what the handler actually returns.
func TestOpenAPISpec_MatchesResponseShape(t *testing.T) {
	rec := httptest.NewRecorder()
	srv := newMetricsTestServer(t)
	srv.handleOpenAPI(rec, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&spec); err != nil {
		t.Fatalf("decoding openapi.json: %v", err)
	}

	req := spec.Components.Schemas["EvaluateRequest"].Properties
	if _, present := req["trace"]; present {
		t.Error("EvaluateRequest still documents a trace property")
	}

	resp := spec.Components.Schemas["EvaluateResponse"].Properties
	for _, key := range []string{"summary", "evaluation_mode", "terminated_early"} {
		if _, present := resp[key]; !present {
			t.Errorf("EvaluateResponse does not document %q", key)
		}
	}

	rule := spec.Components.Schemas["RuleResult"].Properties
	for _, key := range []string{"findings", "findings_truncated"} {
		if _, present := rule[key]; !present {
			t.Errorf("RuleResult does not document %q", key)
		}
	}
	finding := spec.Components.Schemas["Finding"].Properties
	for _, key := range []string{"path", "index", "details"} {
		if _, present := finding[key]; !present {
			t.Errorf("Finding does not document %q", key)
		}
	}
}

// TestHandleEvaluate_ReturnsFindings is the end-to-end check that a rule's
// structured findings reach an HTTP client.
func TestHandleEvaluate_ReturnsFindings(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	policy := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "findings", namespace: "default"}
spec: {
	description: "d"
	target: resources: [{kind: "*"}]
	rules: [{
		id: "r1", description: "d", severity: "high"
		expr: forEach: {path: "xs", as: "x", condition: match: {path: "x.ok", equals: true}}
		details: {name: "x.name"}
	}]
	enforcement: action: "deny"
}`
	if err := eng.LoadPolicy(context.Background(), "findings", "default", policy); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"xs": []any{map[string]any{"name": "a", "ok": true}, map[string]any{"name": "b", "ok": false}}},
	})
	defer resp.Body.Close()
	body := decodeJSON(t, resp)

	results := body["results"].([]any)
	findings, _ := results[0].(map[string]any)["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	f := findings[0].(map[string]any)
	if f["path"] != "xs[1]" || f["details"].(map[string]any)["name"] != "b" {
		t.Errorf("finding = %v, want xs[1] with name b", f)
	}
}
