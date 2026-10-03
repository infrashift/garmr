package engine

import (
	"context"
	"strings"
	"testing"
	"time"
)

// evalRule loads a single-rule policy and evaluates input against it,
// returning the decision and the first result's message.
//
// Rules here deliberately omit `message:`, because a rule-supplied message
// replaces the engine's diagnostic reason (see evaluateRule). These tests
// assert on the reason.
func evalRule(t *testing.T, rule string, input map[string]any) (Decision, string) {
	t.Helper()

	source := makePolicy("fc", "default", "fail-closed test", rule, "deny", "")
	eng := loadTestPolicy(t, "fc", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   input,
		Options: EvaluateOptions{IncludePassed: true},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("no results returned")
	}
	return resp.Decision, resp.Results[0].Message
}

// TestFunc_FalseyResultsFail covers builtins used without `expect:`. The
// previous implementation only tested for bool and nil, so every other type
// fell through to "pass" — a `len` returning 0 silently satisfied the rule.
func TestFunc_FalseyResultsFail(t *testing.T) {
	tests := []struct {
		name       string
		rule       string
		input      map[string]any
		wantDenied bool
	}{
		{
			name:       "len of empty list is falsey",
			rule:       `{id: "r1", description: "d", severity: "high", expr: {func: {name: "len", args: [{path: "items"}]}}}`,
			input:      map[string]any{"items": []any{}},
			wantDenied: true,
		},
		{
			name:       "len of non-empty list is truthy",
			rule:       `{id: "r1", description: "d", severity: "high", expr: {func: {name: "len", args: [{path: "items"}]}}}`,
			input:      map[string]any{"items": []any{"a"}},
			wantDenied: false,
		},
		{
			name:       "empty string is falsey",
			rule:       `{id: "r1", description: "d", severity: "high", expr: {func: {name: "lower", args: [{path: "name"}]}}}`,
			input:      map[string]any{"name": ""},
			wantDenied: true,
		},
		{
			name:       "non-empty string is truthy",
			rule:       `{id: "r1", description: "d", severity: "high", expr: {func: {name: "lower", args: [{path: "name"}]}}}`,
			input:      map[string]any{"name": "Web"},
			wantDenied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, msg := evalRule(t, tt.rule, tt.input)
			denied := decision == DecisionDeny
			if denied != tt.wantDenied {
				t.Errorf("decision = %v (denied=%v), want denied=%v; message=%q", decision, denied, tt.wantDenied, msg)
			}
		})
	}
}

// TestMatch_NumericOperatorOnNonNumericFailsWithReason pins that malformed
// operands fail closed *and say why*. Previously the decode error was
// discarded, so a string field compared with greaterThan silently became
// 0 <= 0 and produced a misleading message.
func TestMatch_NumericOperatorOnNonNumericFailsWithReason(t *testing.T) {
	operators := []string{"greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual"}

	for _, op := range operators {
		t.Run(op+" on string field", func(t *testing.T) {
			rule := `{id: "r1", description: "d", severity: "high", expr: {match: {path: "spec.name", ` + op + `: 3}}}`
			decision, msg := evalRule(t, rule, map[string]any{
				"spec": map[string]any{"name": "web"},
			})

			if decision != DecisionDeny {
				t.Errorf("decision = %v, want %v", decision, DecisionDeny)
			}
			if !strings.Contains(msg, "not numeric") {
				t.Errorf("message = %q, want it to explain the operand is not numeric", msg)
			}
			if !strings.Contains(msg, `"web"`) {
				t.Errorf("message = %q, want it to include the offending value", msg)
			}
		})

		t.Run(op+" on numeric field still compares", func(t *testing.T) {
			rule := `{id: "r1", description: "d", severity: "high", expr: {match: {path: "spec.replicas", ` + op + `: 3}}}`
			_, msg := evalRule(t, rule, map[string]any{
				"spec": map[string]any{"replicas": 5.0},
			})
			if strings.Contains(msg, "not numeric") {
				t.Errorf("message = %q, want a real comparison, not a decode failure", msg)
			}
		})
	}
}

// TestCompare_UnknownValueSourceRejectedAtLoad covers the `data:` value
// source, which was declared in the policy schema but never implemented. It
// used to resolve to nil silently; it is now refused when the policy loads.
func TestCompare_UnknownValueSourceRejectedAtLoad(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high", expr: {compare: {left: {path: "a"}, op: "==", right: {data: "somewhere"}}}}`
	src := makePolicy("p", "default", "d", rule, "deny", "")
	if err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", src); err == nil {
		t.Error("policy with an unknown value source loaded; it must be rejected")
	}
}

// TestCompare_UnknownBuiltinRejectedAtLoad ensures a typo'd builtin name is
// refused when the policy loads rather than resolving to nil per request.
func TestCompare_UnknownBuiltinRejectedAtLoad(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high", expr: {compare: {left: {func: {name: "lenn", args: [{path: "a"}]}}, op: ">", right: {literal: 0}}}}`
	src := makePolicy("p", "default", "d", rule, "deny", "")
	if err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", src); err == nil {
		t.Error("policy with an unknown builtin loaded; it must be rejected")
	}
}

// TestResolveValue_PropagatesContext verifies a builtin invoked from a compare
// operand observes the caller's context. Previously resolveValue passed
// context.Background(), so builtins could not be cancelled by the evaluation
// deadline or a disconnecting client.
func TestResolveValue_PropagatesContext(t *testing.T) {
	eng := newTestEngine(t)

	gotCancelled := make(chan bool, 1)
	// Override a real builtin: names are checked against the schema.
	eng.builtins["now"] = func(ctx context.Context, args ...any) (any, error) {
		select {
		case <-ctx.Done():
			gotCancelled <- true
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			gotCancelled <- false
			return true, nil
		}
	}

	source := makePolicy("ctx", "default", "context propagation",
		`{id: "r1", description: "d", severity: "high", expr: {compare: {left: {func: {name: "now"}}, op: "==", right: {literal: true}}}}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "ctx", "default", source); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := eng.Evaluate(ctx, &EvaluateRequest{Input: map[string]any{"a": 1.0}}); err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	select {
	case cancelled := <-gotCancelled:
		if !cancelled {
			t.Error("builtin ran to completion; the evaluation context was not propagated to it")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("builtin never reported; it was probably never invoked")
	}
}

// TestBuiltinResultTruthy is a direct unit test of the truthiness rule, since
// the policy-level tests can only reach the types the builtins actually
// return.
func TestBuiltinResultTruthy(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"nil", nil, false},
		{"false", false, false},
		{"true", true, true},
		{"zero int", 0, false},
		{"non-zero int", 3, true},
		{"zero float", 0.0, false},
		{"non-zero float", 0.5, true},
		{"empty string", "", false},
		{"non-empty string", "x", true},
		{"string zero stays truthy", "0", true},
		{"empty list", []any{}, false},
		{"non-empty list", []any{1}, true},
		{"empty map", map[string]any{}, false},
		{"non-empty map", map[string]any{"a": 1}, true},
		{"zero time", time.Time{}, false},
		{"non-zero time", time.Unix(1, 0), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := builtinResultTruthy(tt.value)
			if got != tt.want {
				t.Errorf("builtinResultTruthy(%#v) = %v (reason %q), want %v", tt.value, got, reason, tt.want)
			}
			if !got && reason == "" {
				t.Error("falsey result returned no reason")
			}
		})
	}
}
