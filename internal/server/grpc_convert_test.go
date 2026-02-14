package server

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	policypb "github.com/infrashift/garmr/api/proto"
	"github.com/infrashift/garmr/internal/engine"
)

func TestProtoEvalRequestToEngine(t *testing.T) {
	input, _ := structpb.NewStruct(map[string]any{
		"env": "prod",
		"replicas": 3,
	})

	dryRun := true
	req := &policypb.EvaluateRequest{
		Input:       input,
		Namespace:   "security",
		PolicyNames: []string{"pol-1"},
		Options: &policypb.EvaluateOptions{
			Trace:         true,
			IncludePassed: true,
			Strict:        true,
			DryRun:        &dryRun,
		},
	}

	result, err := protoEvalRequestToEngine(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Input["env"] != "prod" {
		t.Errorf("input.env = %v, want prod", result.Input["env"])
	}
	if result.Namespace != "security" {
		t.Errorf("namespace = %v, want security", result.Namespace)
	}
	if len(result.Policies) != 1 || result.Policies[0] != "pol-1" {
		t.Errorf("policies = %v, want [pol-1]", result.Policies)
	}
	if !result.Options.Trace {
		t.Error("expected trace=true")
	}
	if !result.Options.IncludePassed {
		t.Error("expected include_passed=true")
	}
	if !result.Options.Strict {
		t.Error("expected strict=true")
	}
	if result.Options.DryRunOverride == nil || !*result.Options.DryRunOverride {
		t.Error("expected dry_run=true")
	}
}

func TestProtoEvalRequestToEngineNilInput(t *testing.T) {
	req := &policypb.EvaluateRequest{}
	result, err := protoEvalRequestToEngine(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Input != nil {
		t.Errorf("expected nil input, got %v", result.Input)
	}
}

func TestProtoEvalRequestToEngineNilOptions(t *testing.T) {
	input, _ := structpb.NewStruct(map[string]any{"x": 1})
	req := &policypb.EvaluateRequest{
		Input: input,
	}
	result, err := protoEvalRequestToEngine(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Options.Trace {
		t.Error("expected trace=false with nil options")
	}
}

func TestEngineDecisionToProto(t *testing.T) {
	tests := []struct {
		input engine.Decision
		want  policypb.Decision
	}{
		{engine.DecisionAllow, policypb.Decision_DECISION_ALLOW},
		{engine.DecisionDeny, policypb.Decision_DECISION_DENY},
		{engine.DecisionWarn, policypb.Decision_DECISION_WARN},
		{"unknown", policypb.Decision_DECISION_UNSPECIFIED},
	}
	for _, tt := range tests {
		got := engineDecisionToProto(tt.input)
		if got != tt.want {
			t.Errorf("engineDecisionToProto(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEngineSeverityToProto(t *testing.T) {
	tests := []struct {
		input engine.Severity
		want  policypb.Severity
	}{
		{engine.SeverityCritical, policypb.Severity_SEVERITY_CRITICAL},
		{engine.SeverityHigh, policypb.Severity_SEVERITY_HIGH},
		{engine.SeverityMedium, policypb.Severity_SEVERITY_MEDIUM},
		{engine.SeverityLow, policypb.Severity_SEVERITY_LOW},
		{engine.SeverityInfo, policypb.Severity_SEVERITY_INFO},
		{"unknown", policypb.Severity_SEVERITY_UNSPECIFIED},
	}
	for _, tt := range tests {
		got := engineSeverityToProto(tt.input)
		if got != tt.want {
			t.Errorf("engineSeverityToProto(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEngineRuleResultToProto(t *testing.T) {
	r := &engine.RuleResult{
		PolicyName:      "my-policy",
		PolicyNamespace: "ns",
		RuleID:          "r1",
		RuleDescription: "check something",
		Severity:        engine.SeverityHigh,
		Passed:          false,
		Message:         "failed check",
		Bindings: map[string]any{
			"key": "value",
		},
	}

	pr := engineRuleResultToProto(r)
	if pr.PolicyName != "my-policy" {
		t.Errorf("policy_name = %v", pr.PolicyName)
	}
	if pr.RuleId != "r1" {
		t.Errorf("rule_id = %v", pr.RuleId)
	}
	if pr.Severity != policypb.Severity_SEVERITY_HIGH {
		t.Errorf("severity = %v", pr.Severity)
	}
	if pr.Passed {
		t.Error("expected passed=false")
	}
	if len(pr.Bindings) != 1 {
		t.Errorf("expected 1 binding, got %d", len(pr.Bindings))
	}
}

func TestEngineRuleResultToProtoEmptyBindings(t *testing.T) {
	r := &engine.RuleResult{
		PolicyName: "p",
		Passed:     true,
	}
	pr := engineRuleResultToProto(r)
	if len(pr.Bindings) != 0 {
		t.Errorf("expected no bindings, got %d", len(pr.Bindings))
	}
}

func TestEngineEvalResponseToProto(t *testing.T) {
	resp := &engine.EvaluateResponse{
		Decision: engine.DecisionDeny,
		Results: []engine.RuleResult{
			{PolicyName: "p1", Passed: false, Severity: engine.SeverityHigh},
		},
		Metrics: &engine.Metrics{
			EvaluationTimeNs:  12345,
			PoliciesEvaluated: 2,
			RulesEvaluated:    5,
		},
	}

	pr := engineEvalResponseToProto(resp)
	if pr.Decision != policypb.Decision_DECISION_DENY {
		t.Errorf("decision = %v", pr.Decision)
	}
	if len(pr.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(pr.Results))
	}
	if pr.Metrics == nil {
		t.Fatal("expected metrics")
	}
	if pr.Metrics.PoliciesEvaluated != 2 {
		t.Errorf("policies_evaluated = %d", pr.Metrics.PoliciesEvaluated)
	}
}

func TestEngineEvalResponseToProtoNilMetrics(t *testing.T) {
	resp := &engine.EvaluateResponse{
		Decision: engine.DecisionAllow,
	}
	pr := engineEvalResponseToProto(resp)
	if pr.Metrics != nil {
		t.Error("expected nil metrics")
	}
}

func TestEnginePolicyToProtoInfo(t *testing.T) {
	now := time.Now()
	p := &engine.CompiledPolicy{
		Name:      "test",
		Namespace: "ns",
		Hash:      "abc123",
		Rules:     make([]engine.CompiledRule, 3),
		LoadedAt:  now,
	}

	info := enginePolicyToProtoInfo(p)
	if info.Name != "test" {
		t.Errorf("name = %v", info.Name)
	}
	if info.RuleCount != 3 {
		t.Errorf("rule_count = %d", info.RuleCount)
	}
	if info.Hash != "abc123" {
		t.Errorf("hash = %v", info.Hash)
	}
}

func TestEngineValidationErrorsToProto(t *testing.T) {
	errs := []engine.ValidationError{
		{Message: "error1", Line: 5, Column: 10, Filename: "policy.cue"},
		{Message: "error2"},
	}

	result := engineValidationErrorsToProto(errs)
	if len(result) != 2 {
		t.Fatalf("expected 2 errors, got %d", len(result))
	}
	if result[0].Position == nil {
		t.Error("expected position for error with line>0")
	}
	if result[0].Position.Line != 5 {
		t.Errorf("line = %d", result[0].Position.Line)
	}
	if result[1].Position != nil {
		t.Error("expected nil position for error without line/column")
	}
}

func TestEngineValidationErrorsToProtoNil(t *testing.T) {
	result := engineValidationErrorsToProto(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestBindingsToProtoNil(t *testing.T) {
	result := bindingsToProto(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestBindingsToProtoEmpty(t *testing.T) {
	result := bindingsToProto(map[string]any{})
	if result != nil {
		t.Errorf("expected nil for empty map, got %v", result)
	}
}
