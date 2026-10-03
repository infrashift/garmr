package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infrashift/garmr/internal/engine"
)

// wireBody renders a response body to JSON and back, so tests assert the
// shape clients actually receive.
func wireBody(t *testing.T, body any) map[string]any {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// TestEvaluateResponseBody_CarriesSummaryAndMode pins the fields the engine
// has always computed but the API never returned. `garmr eval --help`
// promises that the response says whether fail-fast triggered, which rule
// caused termination, and how many rules were skipped.
func TestEvaluateResponseBody_CarriesSummaryAndMode(t *testing.T) {
	result := &engine.EvaluateResponse{
		Decision: engine.DecisionDeny,
		Results: []engine.RuleResult{
			{PolicyName: "p", PolicyNamespace: "ns", RuleID: "R-001", Severity: engine.SeverityHigh, Passed: false, Message: "boom"},
		},
		Metrics: &engine.Metrics{PoliciesEvaluated: 1, RulesEvaluated: 1},
	}
	result.Summary.TotalRules = 5
	result.Summary.Passed = 0
	result.Summary.Failed = 1
	result.Summary.Skipped = 4
	result.EvaluationMode.FailFast = true
	result.EvaluationMode.ShortCircuited = true
	result.EvaluationMode.TotalRulesInScope = 5
	result.EvaluationMode.RulesEvaluated = 1
	result.EvaluationMode.RulesSkipped = 4
	result.TerminatedEarly = true
	result.TerminationRule = &engine.RuleResult{
		PolicyName: "p", PolicyNamespace: "ns", RuleID: "R-001", Severity: engine.SeverityHigh, Message: "boom",
	}

	body := wireBody(t, evaluateResponseBody(result, "req-1"))

	if body["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", body["decision"])
	}
	if body["terminated_early"] != true {
		t.Error("terminated_early missing or false")
	}

	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing or wrong type: %T", body["summary"])
	}
	for key, want := range map[string]float64{"total_rules": 5, "passed": 0, "failed": 1, "skipped": 4} {
		if summary[key] != want {
			t.Errorf("summary[%q] = %v, want %v", key, summary[key], want)
		}
	}

	mode, ok := body["evaluation_mode"].(map[string]any)
	if !ok {
		t.Fatalf("evaluation_mode missing or wrong type: %T", body["evaluation_mode"])
	}
	if mode["fail_fast"] != true || mode["short_circuited"] != true {
		t.Errorf("evaluation_mode = %v, want fail_fast and short_circuited true", mode)
	}
	if mode["rules_skipped"] != 4.0 || mode["rules_evaluated"] != 1.0 {
		t.Errorf("evaluation_mode counts = %v, want 1 evaluated / 4 skipped", mode)
	}

	tr, ok := body["termination_rule"].(map[string]any)
	if !ok {
		t.Fatalf("termination_rule missing or wrong type: %T", body["termination_rule"])
	}
	if tr["rule_id"] != "R-001" {
		t.Errorf("termination_rule.rule_id = %v, want R-001", tr["rule_id"])
	}
}

// TestEvaluateResponseBody_OmitsTerminationRuleWhenAbsent keeps the field out
// of the body for the ordinary case rather than emitting a null.
func TestEvaluateResponseBody_OmitsTerminationRuleWhenAbsent(t *testing.T) {
	result := &engine.EvaluateResponse{Decision: engine.DecisionAllow}

	body := wireBody(t, evaluateResponseBody(result, "req-2"))

	if _, present := body["termination_rule"]; present {
		t.Error("termination_rule present when the evaluation did not terminate early")
	}
	if body["terminated_early"] != false {
		t.Error("terminated_early should be false")
	}
	if _, present := body["metrics"]; present {
		t.Error("metrics present when the engine returned none")
	}
}

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
}
