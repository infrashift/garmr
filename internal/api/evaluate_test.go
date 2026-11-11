package api

import (
	"encoding/json"
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

	body := wireBody(t, NewEvaluateBody(result, "req-1"))

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

	body := wireBody(t, NewEvaluateBody(result, "req-2"))

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

func TestNewEvaluateBody_Findings(t *testing.T) {
	result := &engine.EvaluateResponse{
		Decision: engine.DecisionDeny,
		Results: []engine.RuleResult{
			{RuleID: "with", Findings: []engine.Finding{{Path: "xs[2]", Index: 2, Details: map[string]any{"file": "a.go"}}}, FindingsTruncated: true},
			{RuleID: "without"},
		},
	}
	body := wireBody(t, NewEvaluateBody(result, "req-3"))
	results := body["results"].([]any)

	with := results[0].(map[string]any)
	findings, ok := with["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %v, want one", with["findings"])
	}
	f := findings[0].(map[string]any)
	if f["path"] != "xs[2]" || f["index"] != 2.0 || f["details"].(map[string]any)["file"] != "a.go" {
		t.Errorf("finding = %v", f)
	}
	if with["findings_truncated"] != true {
		t.Error("findings_truncated missing")
	}

	without := results[1].(map[string]any)
	if _, present := without["findings"]; present {
		t.Error("findings present on a rule that reported none")
	}
	if _, present := without["findings_truncated"]; present {
		t.Error("findings_truncated present on a rule that reported none")
	}
}

func TestNewEvaluateBody_Waived(t *testing.T) {
	result := &engine.EvaluateResponse{Results: []engine.RuleResult{
		{RuleID: "r", Passed: true, Waived: []engine.Finding{{Path: "xs[0]", Exception: "accepted"}}},
	}}
	body := wireBody(t, NewEvaluateBody(result, "req-4"))
	waived, _ := body["results"].([]any)[0].(map[string]any)["waived"].([]any)
	if len(waived) != 1 || waived[0].(map[string]any)["exception"] != "accepted" {
		t.Errorf("waived = %v, want one entry naming the exception", waived)
	}
}
