package engine

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// testPolicyCUE is a template for creating test policies.
// The CUE source must be a bare policy struct (no wrapping key) for LoadPolicy.
const testPolicyCUE = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "%s"
	namespace: "%s"
}
spec: {
	description: "%s"
	target: resources: [{kind: "*"}]
	rules: [%s]
	enforcement: {
		action: "%s"
		%s
	}
	%s
}
`

// makePolicy creates a CUE policy string. enfExtra goes inside enforcement{}, evalExtra goes inside spec{}.
func makePolicyFull(name, namespace, description, rules, action, enfExtra, evalExtra string) string {
	return fmt.Sprintf(testPolicyCUE, name, namespace, description, rules, action, enfExtra, evalExtra)
}

// makePolicy creates a CUE policy with the given params.
// extra goes into the spec block as evaluation config or other spec-level fields.
func makePolicy(name, namespace, description, rules, action, extra string) string {
	return makePolicyFull(name, namespace, description, rules, action, "", extra)
}

// loadTestPolicy creates a fresh engine, loads a CUE policy string, and returns the engine.
func loadTestPolicy(t *testing.T, name, namespace, source string) *Engine {
	t.Helper()
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if err := eng.LoadPolicy(context.Background(), name, namespace, source); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	return eng
}

// --- Engine Lifecycle ---

func TestNewEngine(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if eng == nil {
		t.Fatal("engine is nil")
	}
	if len(eng.builtins) == 0 {
		t.Error("no builtins registered")
	}
}

func TestNewEngine_NilLogger(t *testing.T) {
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine with nil logger failed: %v", err)
	}
	if eng == nil {
		t.Fatal("engine is nil")
	}
}

// --- Policy Loading ---

func TestLoadPolicy(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	source := makePolicy("test-policy", "default", "A test policy",
		`{
			id: "rule-1"
			description: "check name"
			severity: "high"
			expr: { match: { path: "name", equals: "test" } }
			message: "name must be test"
		}`,
		"deny", "")

	err = eng.LoadPolicy(context.Background(), "test-policy", "default", source)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "test-policy" {
		t.Errorf("expected name=test-policy, got %s", policies[0].Name)
	}
}

func TestGetPolicy(t *testing.T) {
	source := makePolicy("my-policy", "prod", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "my-policy", "prod", source)

	p, err := eng.GetPolicy("prod", "my-policy")
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p.Name != "my-policy" {
		t.Errorf("expected name=my-policy, got %s", p.Name)
	}

	// Not found
	_, err = eng.GetPolicy("prod", "nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestDeletePolicy(t *testing.T) {
	source := makePolicy("del-me", "default", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "del-me", "default", source)

	ok := eng.DeletePolicy("default", "del-me")
	if !ok {
		t.Error("expected DeletePolicy to return true")
	}
	if len(eng.ListPolicies("")) != 0 {
		t.Error("expected no policies after delete")
	}

	// Delete nonexistent
	ok = eng.DeletePolicy("default", "nope")
	if ok {
		t.Error("expected false for deleting nonexistent policy")
	}
}

func TestClearPolicies(t *testing.T) {
	source := makePolicy("p1", "default", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "p1", "default", source)

	eng.ClearPolicies()
	if len(eng.ListPolicies("")) != 0 {
		t.Error("expected no policies after clear")
	}
}

func TestListPolicies_NamespaceFilter(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	source1 := makePolicy("p1", "ns1", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	source2 := makePolicy("p2", "ns2", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")

	eng.LoadPolicy(context.Background(), "p1", "ns1", source1)
	eng.LoadPolicy(context.Background(), "p2", "ns2", source2)

	if len(eng.ListPolicies("")) != 2 {
		t.Error("expected 2 policies total")
	}
	if len(eng.ListPolicies("ns1")) != 1 {
		t.Error("expected 1 policy in ns1")
	}
	if len(eng.ListPolicies("ns2")) != 1 {
		t.Error("expected 1 policy in ns2")
	}
	if len(eng.ListPolicies("ns3")) != 0 {
		t.Error("expected 0 policies in ns3")
	}
}

// --- Validation ---

func TestValidate_ValidPolicy(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	source := makePolicy("valid", "default", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	errors, _ := eng.Validate(source)
	if len(errors) != 0 {
		t.Errorf("expected no errors, got %v", errors)
	}
}

func TestValidate_InvalidPolicy(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	errors, _ := eng.Validate("{ invalid cue !!! }")
	if len(errors) == 0 {
		t.Error("expected validation errors for invalid CUE")
	}
}

// --- Expression Evaluation: Match Operators ---

func TestEvaluate_MatchEquals(t *testing.T) {
	source := makePolicy("eq-test", "default", "equals test",
		`{id: "r1", description: "check env", severity: "high", expr: {match: {path: "env", equals: "prod"}}, message: "env must be prod"}`,
		"deny", "")
	eng := loadTestPolicy(t, "eq-test", "default", source)

	// Pass
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"env": "prod"},
		Options: EvaluateOptions{IncludePassed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	// Fail
	resp, err = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchEquals_Numeric(t *testing.T) {
	source := makePolicy("num-eq", "default", "numeric equals",
		`{id: "r1", description: "check count", severity: "high", expr: {match: {path: "count", equals: 5}}, message: "count must be 5"}`,
		"deny", "")
	eng := loadTestPolicy(t, "num-eq", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"count": 5.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for count=5, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchGreaterThan(t *testing.T) {
	source := makePolicy("gt-test", "default", "gt test",
		`{id: "r1", description: "check replicas", severity: "medium", expr: {match: {path: "replicas", greaterThan: 0}}, message: "replicas must be > 0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "gt-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 3.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for replicas=3, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 0.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for replicas=0, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLessThan(t *testing.T) {
	source := makePolicy("lt-test", "default", "lt test",
		`{id: "r1", description: "check max", severity: "low", expr: {match: {path: "value", lessThan: 100}}, message: "value must be < 100"}`,
		"deny", "")
	eng := loadTestPolicy(t, "lt-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"value": 50.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for value=50, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"value": 100.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for value=100, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchIn(t *testing.T) {
	source := makePolicy("in-test", "default", "in test",
		`{id: "r1", description: "check env", severity: "high", expr: {match: {path: "env", in: ["prod", "staging"]}}, message: "env must be prod or staging"}`,
		"deny", "")
	eng := loadTestPolicy(t, "in-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for env=prod, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for env=dev, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchNotIn(t *testing.T) {
	source := makePolicy("notin-test", "default", "notIn test",
		`{id: "r1", description: "block envs", severity: "high", expr: {match: {path: "env", notIn: ["dev", "test"]}}, message: "env forbidden"}`,
		"deny", "")
	eng := loadTestPolicy(t, "notin-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for env=prod, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for env=dev, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchContains(t *testing.T) {
	source := makePolicy("contains-test", "default", "contains test",
		`{id: "r1", description: "check name", severity: "low", expr: {match: {path: "name", contains: "app"}}, message: "name must contain app"}`,
		"deny", "")
	eng := loadTestPolicy(t, "contains-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"name": "my-app-service"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchPattern(t *testing.T) {
	source := makePolicy("pattern-test", "default", "pattern test",
		`{id: "r1", description: "check version", severity: "medium", expr: {match: {path: "version", pattern: "^v\\d+\\.\\d+\\.\\d+$"}}, message: "version must match semver"}`,
		"deny", "")
	eng := loadTestPolicy(t, "pattern-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "v1.2.3"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "latest"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Exists / Absent ---

func TestEvaluate_Exists(t *testing.T) {
	source := makePolicy("exists-test", "default", "exists test",
		`{id: "r1", description: "check labels", severity: "high", expr: {exists: "metadata.labels"}, message: "labels required"}`,
		"deny", "")
	eng := loadTestPolicy(t, "exists-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "test"}}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"metadata": map[string]any{}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Absent(t *testing.T) {
	source := makePolicy("absent-test", "default", "absent test",
		`{id: "r1", description: "check hostNetwork", severity: "critical", expr: {absent: "spec.hostNetwork"}, message: "hostNetwork must not be set"}`,
		"deny", "")
	eng := loadTestPolicy(t, "absent-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{"hostNetwork": true}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Logical Combinators ---

func TestEvaluate_All(t *testing.T) {
	source := makePolicy("all-test", "default", "all test",
		`{id: "r1", description: "all conditions", severity: "high", expr: {all: [
			{match: {path: "a", equals: 1}},
			{match: {path: "b", equals: 2}}
		]}, message: "all must match"}`,
		"deny", "")
	eng := loadTestPolicy(t, "all-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"a": 1.0, "b": 2.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"a": 1.0, "b": 3.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Any(t *testing.T) {
	source := makePolicy("any-test", "default", "any test",
		`{id: "r1", description: "any condition", severity: "high", expr: {any: [
			{match: {path: "env", equals: "prod"}},
			{match: {path: "env", equals: "staging"}}
		]}, message: "env must be prod or staging"}`,
		"deny", "")
	eng := loadTestPolicy(t, "any-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "staging"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Not(t *testing.T) {
	source := makePolicy("not-test", "default", "not test",
		`{id: "r1", description: "not dev", severity: "high", expr: {not: {match: {path: "env", equals: "dev"}}}, message: "must not be dev"}`,
		"deny", "")
	eng := loadTestPolicy(t, "not-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- ForEach ---

func TestEvaluate_ForEach(t *testing.T) {
	source := makePolicy("foreach-test", "default", "forEach test",
		`{
			id: "r1"
			description: "all containers must have image"
			severity: "high"
			expr: {forEach: {
				path: "spec.containers"
				as: "container"
				condition: {exists: "container.image"}
			}}
			message: "all containers need image"
		}`,
		"deny", "")
	eng := loadTestPolicy(t, "foreach-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{"name": "app", "image": "nginx"},
					map[string]any{"name": "sidecar", "image": "envoy"},
				},
			},
		},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}

// --- Contains Expression ---

func TestEvaluate_ContainsExpr(t *testing.T) {
	source := makePolicy("contains-expr", "default", "contains expr test",
		`{id: "r1", description: "check tags", severity: "medium", expr: {contains: {path: "tags", value: "production"}}, message: "must have production tag"}`,
		"deny", "")
	eng := loadTestPolicy(t, "contains-expr", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tags": []any{"production", "reviewed"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tags": []any{"staging"}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Compare Expression ---

func TestEvaluate_Compare(t *testing.T) {
	source := makePolicy("compare-test", "default", "compare test",
		`{id: "r1", description: "compare values", severity: "high", expr: {compare: {
			left: {path: "replicas"}
			op: ">="
			right: {literal: 2}
		}}, message: "replicas must be >= 2"}`,
		"deny", "")
	eng := loadTestPolicy(t, "compare-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 3.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 1.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Func Expression ---

func TestEvaluate_Func(t *testing.T) {
	source := makePolicy("func-test", "default", "func test",
		`{id: "r1", description: "check length", severity: "medium", expr: {func: {
			name: "len"
			args: ["input.items"]
			expect: 3
		}}, message: "must have exactly 3 items"}`,
		"deny", "")
	eng := loadTestPolicy(t, "func-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b", "c"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b"}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Decision Logic ---

func TestEvaluate_AllRulesPass_Allow(t *testing.T) {
	source := makePolicy("allow-test", "default", "allow test",
		`{id: "r1", description: "pass", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "allow-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}

func TestEvaluate_DenyEnforcement_Deny(t *testing.T) {
	source := makePolicy("deny-test", "default", "deny test",
		`{id: "r1", description: "fail", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", "")
	eng := loadTestPolicy(t, "deny-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
	if len(resp.Results) == 0 {
		t.Error("expected results with violation")
	}
}

func TestEvaluate_WarnEnforcement_Warn(t *testing.T) {
	source := makePolicy("warn-test", "default", "warn test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "x should be 1"}`,
		"warn", "")
	eng := loadTestPolicy(t, "warn-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	if resp.Decision != DecisionWarn {
		t.Errorf("expected warn, got %s", resp.Decision)
	}
}

func TestEvaluate_IncludePassed(t *testing.T) {
	source := makePolicy("incl-test", "default", "include passed",
		`{id: "r1", description: "pass", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "incl-test", "default", source)

	// Without IncludePassed
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1.0},
	})
	if len(resp.Results) != 0 {
		t.Error("expected no results without IncludePassed")
	}

	// With IncludePassed
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 1.0},
		Options: EvaluateOptions{IncludePassed: true},
	})
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result with IncludePassed, got %d", len(resp.Results))
	}
}

// --- Fail-Fast ---

func TestEvaluate_FailFast(t *testing.T) {
	source := makePolicyFull("ff-test", "default", "fail fast test",
		`{id: "r1", description: "first", severity: "high", expr: {match: {path: "x", equals: 999}}, message: "first fails"},
		{id: "r2", description: "second", severity: "medium", expr: {match: {path: "y", equals: 999}}, message: "second fails"},
		{id: "r3", description: "third", severity: "low", expr: {match: {path: "z", equals: 999}}, message: "third fails"}`,
		"deny", "", `evaluation: failFast: true`)
	eng := loadTestPolicy(t, "ff-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 0.0, "y": 0.0, "z": 0.0},
	})
	if !resp.TerminatedEarly {
		t.Error("expected TerminatedEarly to be true")
	}
	if resp.EvaluationMode.RulesSkipped == 0 {
		t.Error("expected some skipped rules")
	}
	// Should only have evaluated 1 rule (the first failure)
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result with fail-fast, got %d", len(resp.Results))
	}
}

// --- Dry Run ---

func TestEvaluate_DryRun(t *testing.T) {
	source := makePolicyFull("dr-test", "default", "dry run test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", `dryRun: true`, "")
	eng := loadTestPolicy(t, "dr-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	// Dry run: deny should be downgraded to warn
	if resp.Decision != DecisionWarn {
		t.Errorf("expected warn (dry run), got %s", resp.Decision)
	}
	if !resp.EvaluationMode.DryRun {
		t.Error("expected DryRun mode to be true")
	}
	if len(resp.Results) > 0 && resp.Results[0].Message != "" {
		if len(resp.Results[0].Message) < 10 || resp.Results[0].Message[:10] != "[DRY RUN] " {
			t.Errorf("expected message to start with [DRY RUN], got: %s", resp.Results[0].Message)
		}
	}
}

func TestEvaluate_DryRunOverride(t *testing.T) {
	// Policy is NOT dry run, but override is set
	source := makePolicy("dro-test", "default", "dry run override",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dro-test", "default", source)

	dryRun := true
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 2.0},
		Options: EvaluateOptions{DryRunOverride: &dryRun},
	})
	if resp.Decision != DecisionWarn {
		t.Errorf("expected warn (dry run override), got %s", resp.Decision)
	}
}

// --- Category/Tag Filtering ---

func TestEvaluate_CategoryFilter(t *testing.T) {
	source := makePolicy("cat-test", "default", "category filter test",
		`{id: "r1", description: "security check", severity: "high", category: "security", expr: {match: {path: "x", equals: 1}}, message: "fail"},
		{id: "r2", description: "quality check", severity: "medium", category: "quality", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cat-test", "default", source)

	// Only evaluate security rules
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 2.0},
		Options: EvaluateOptions{IncludeCategories: []string{"security"}},
	})
	// Only the security rule should have been evaluated and failed
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result (security only), got %d", len(resp.Results))
	}
}

func TestEvaluate_TagFilter(t *testing.T) {
	source := makePolicy("tag-test", "default", "tag filter test",
		`{id: "r1", description: "prod check", severity: "high", tags: ["prod"], expr: {match: {path: "x", equals: 1}}, message: "fail"},
		{id: "r2", description: "dev check", severity: "low", tags: ["dev"], expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "tag-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 2.0},
		Options: EvaluateOptions{ExcludeTags: []string{"dev"}},
	})
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result (excluding dev), got %d", len(resp.Results))
	}
}

// --- Exception Handling ---

func TestEvaluate_Exception(t *testing.T) {
	source := makePolicyFull("exc-test", "default", "exception test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "replicas", greaterThan: 0}}, message: "need replicas"}`,
		"deny", `exceptions: [{
			name: "legacy-app"
			reason: "legacy exception"
			match: {kind: "Deployment", names: ["legacy-app"]}
		}]`, "")
	eng := loadTestPolicy(t, "exc-test", "default", source)

	// Input matches exception
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "legacy-app"},
			"replicas": 0.0,
		},
	})
	// Exception matched, so evaluation is skipped — allow
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow (exception), got %s", resp.Decision)
	}

	// Input does NOT match exception
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "new-app"},
			"replicas": 0.0,
		},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny (no exception), got %s", resp.Decision)
	}
}

// --- Timeout Enforcement ---

func TestEvaluate_Timeout(t *testing.T) {
	source := makePolicyFull("timeout-test", "default", "timeout test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "", `evaluation: timeout: "1ns"`)
	eng := loadTestPolicy(t, "timeout-test", "default", source)

	// With an absurdly short timeout, the context should be cancelled
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	// With timeout, the rule may pass (timeout = don't penalize) or be skipped
	_ = resp // Just ensure no panic/error
}

// --- Namespace Filtering ---

func TestEvaluate_NamespaceFilter(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())

	source1 := makePolicy("p1", "ns1", "test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	source2 := makePolicy("p2", "ns2", "test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")

	eng.LoadPolicy(context.Background(), "p1", "ns1", source1)
	eng.LoadPolicy(context.Background(), "p2", "ns2", source2)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:     map[string]any{"x": 2.0},
		Namespace: "ns1",
	})
	// Only 1 policy (ns1) should have been evaluated
	if resp.Metrics.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", resp.Metrics.PoliciesEvaluated)
	}
}

// --- Severity Weights ---

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 75},
		{SeverityMedium, 50},
		{SeverityLow, 25},
		{SeverityInfo, 0},
		{Severity("unknown"), 0},
	}
	for _, tt := range tests {
		if got := tt.severity.Weight(); got != tt.want {
			t.Errorf("%s.Weight() = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

// --- Policy Loading from Directory ---

func TestLoadPoliciesFromDir(t *testing.T) {
	dir := t.TempDir()

	// Write a CUE file with a policy
	policyContent := `package policy

container_security: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "container-security"
		namespace: "default"
	}
	spec: {
		description: "Container security policy"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "cs-1"
			description: "check image"
			severity:    "high"
			expr: {match: {path: "image", equals: "nginx"}}
			message: "image must be nginx"
		}]
		enforcement: action: "deny"
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	eng, _ := NewEngine(zap.NewNop())
	err := eng.LoadPoliciesFromDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("LoadPoliciesFromDir failed: %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) == 0 {
		t.Error("expected at least 1 policy loaded from dir")
	}
}

func TestReloadPoliciesFromDir(t *testing.T) {
	dir := t.TempDir()

	policyContent := `package policy

test_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "test"
		namespace: "default"
	}
	spec: {
		description: "test"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "t-1"
			description: "check"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
			message: "fail"
		}]
		enforcement: action: "deny"
	}
}
`
	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(policyContent), 0644)

	eng, _ := NewEngine(zap.NewNop())
	count, err := eng.ReloadPoliciesFromDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromDir failed: %v", err)
	}
	if count == 0 {
		t.Error("expected at least 1 policy reloaded")
	}
}

// --- Metrics ---

func TestEvaluate_Metrics(t *testing.T) {
	source := makePolicy("met-test", "default", "metrics test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "met-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1.0},
	})
	if resp.Metrics == nil {
		t.Fatal("expected non-nil metrics")
	}
	if resp.Metrics.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", resp.Metrics.PoliciesEvaluated)
	}
	if resp.Metrics.RulesEvaluated != 1 {
		t.Errorf("expected 1 rule evaluated, got %d", resp.Metrics.RulesEvaluated)
	}
	if resp.Metrics.EvaluationTimeNs <= 0 {
		t.Error("expected positive evaluation time")
	}
}

// --- Helper function tests ---

func TestValuesEqual(t *testing.T) {
	tests := []struct {
		a, b any
		want bool
	}{
		{1.0, 1.0, true},
		{1.0, 1, true},
		{"hello", "hello", true},
		{1.0, 2.0, false},
		{"a", "b", false},
	}
	for _, tt := range tests {
		if got := valuesEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("valuesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"pod*", "pod-123", true},
		{"exact", "exact", true},
		{"exact", "other", false},
		{"*.apps", "deploy.apps", true},
	}
	for _, tt := range tests {
		if got := matchesPattern(tt.pattern, tt.value); got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

// --- Multifield match exists within match ---

func TestEvaluate_MatchExists(t *testing.T) {
	source := makePolicy("matchexists-test", "default", "match exists test",
		`{id: "r1", description: "field must exist", severity: "high", expr: {match: {path: "spec.replicas", exists: true}}, message: "replicas required"}`,
		"deny", "")
	eng := loadTestPolicy(t, "matchexists-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{"replicas": 3.0}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- GreaterThanOrEqual / LessThanOrEqual ---

func TestEvaluate_MatchGTE(t *testing.T) {
	source := makePolicy("gte-test", "default", "gte test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "v", greaterThanOrEqual: 10}}, message: "must be >= 10"}`,
		"deny", "")
	eng := loadTestPolicy(t, "gte-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 10.0}})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for v=10, got %s", resp.Decision)
	}
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 9.0}})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for v=9, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLTE(t *testing.T) {
	source := makePolicy("lte-test", "default", "lte test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "v", lessThanOrEqual: 100}}, message: "must be <= 100"}`,
		"deny", "")
	eng := loadTestPolicy(t, "lte-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 100.0}})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for v=100, got %s", resp.Decision)
	}
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 101.0}})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for v=101, got %s", resp.Decision)
	}
}

// --- Data operations ---

func TestSetGetData(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())

	err := eng.SetData("", map[string]any{"env": "prod"})
	if err != nil {
		t.Fatalf("SetData failed: %v", err)
	}

	result := eng.GetData("")
	if result == nil {
		t.Error("GetData returned nil")
	}
}

// --- LoadPolicy Error ---

func TestLoadPolicy_InvalidSource(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	err := eng.LoadPolicy(context.Background(), "bad", "default", "!!! invalid CUE !!!")
	if err == nil {
		t.Error("expected error for invalid CUE source")
	}
}

// --- Empty Input ---

func TestEvaluate_NoPolicies(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow with no policies, got %s", resp.Decision)
	}
}

// --- getStringField / getMapField helpers ---

func TestGetStringField(t *testing.T) {
	m := map[string]any{
		"metadata": map[string]any{
			"name": "test",
		},
	}
	if got := getStringField(m, "metadata", "name"); got != "test" {
		t.Errorf("expected 'test', got %q", got)
	}
	if got := getStringField(m, "metadata", "missing"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	if got := getStringField(m, "nonexistent", "name"); got != "" {
		t.Errorf("expected empty for missing path, got %q", got)
	}
}

func TestGetMapField(t *testing.T) {
	m := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				"app": "nginx",
			},
		},
	}
	labels := getMapField(m, "metadata", "labels")
	if labels == nil {
		t.Fatal("expected non-nil labels")
	}
	if labels["app"] != "nginx" {
		t.Errorf("expected app=nginx, got %s", labels["app"])
	}
}

// --- compareDatetime ---

func TestCompareDatetime(t *testing.T) {
	r := compareDatetime("2024-01-15T12:00:00Z", "2024-01-14T12:00:00Z")
	if r <= 0 {
		t.Error("expected 2024-01-15 to be after 2024-01-14")
	}
}

// --- Concurrent evaluations ---

func TestEvaluate_Concurrent(t *testing.T) {
	source := makePolicy("conc-test", "default", "concurrent test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "conc-test", "default", source)

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func(val float64) {
			defer func() { done <- struct{}{} }()
			eng.Evaluate(context.Background(), &EvaluateRequest{
				Input: map[string]any{"x": val},
			})
		}(float64(i))
	}

	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("concurrent evaluations timed out")
		}
	}
}

// --- CUE Context Pool Stress Tests ---

// concurrentResult captures the outcome of a single concurrent evaluation.
type concurrentResult struct {
	WorkerID  int
	RequestID int
	Duration  time.Duration
	Decision  Decision
	Err       error
	RuleCount int
}

// concurrentStats aggregates metrics from a concurrent stress test run.
type concurrentStats struct {
	TotalRequests int
	Successes     int64
	Failures      int64
	AllowCount    int64
	DenyCount     int64
	WarnCount     int64
	Durations     []time.Duration
}

func (s *concurrentStats) compute() (min, max, mean, p50, p95, p99 time.Duration) {
	if len(s.Durations) == 0 {
		return
	}
	sorted := make([]time.Duration, len(s.Durations))
	copy(sorted, s.Durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	min = sorted[0]
	max = sorted[len(sorted)-1]

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	mean = total / time.Duration(len(sorted))

	p50 = sorted[int(math.Ceil(float64(len(sorted))*0.50))-1]
	p95 = sorted[int(math.Ceil(float64(len(sorted))*0.95))-1]
	p99 = sorted[int(math.Ceil(float64(len(sorted))*0.99))-1]
	return
}

// TestConcurrentCueContextPool_StressCorrectness fires 1000 concurrent requests
// against a shared engine with multiple policies, verifying that each evaluation
// returns the correct decision and that no data races or panics occur.
// Run with: go test -v -race -run TestConcurrentCueContextPool_StressCorrectness ./internal/engine/
func TestConcurrentCueContextPool_StressCorrectness(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Load a policy where x == 1 → allow, x != 1 → deny
	policyAllow := makePolicy("check-x", "default", "check x equals 1",
		`{id: "r1", description: "x must be 1", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x is not 1"}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "check-x", "default", policyAllow); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	// Load a second policy to stress multi-policy evaluation
	policyName := makePolicy("check-name", "default", "check name present",
		`{id: "r2", description: "name must exist", severity: "medium", expr: {exists: {path: "name"}}, message: "name missing"}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "check-name", "default", policyName); err != nil {
		t.Fatalf("LoadPolicy check-name: %v", err)
	}

	const totalRequests = 1000
	const concurrency = 50

	results := make([]concurrentResult, totalRequests)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency) // limit in-flight goroutines

	wallStart := time.Now()

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			// Alternate inputs: even → x=1 + name (should allow), odd → x=0 no name (should deny)
			var input map[string]any
			if idx%2 == 0 {
				input = map[string]any{"x": float64(1), "name": fmt.Sprintf("item-%d", idx)}
			} else {
				input = map[string]any{"x": float64(0)}
			}

			start := time.Now()
			resp, evalErr := eng.Evaluate(context.Background(), &EvaluateRequest{
				Input: input,
			})
			elapsed := time.Since(start)

			r := concurrentResult{
				WorkerID:  idx % concurrency,
				RequestID: idx,
				Duration:  elapsed,
				Err:       evalErr,
			}
			if resp != nil {
				r.Decision = resp.Decision
				r.RuleCount = len(resp.Results)
			}
			results[idx] = r
		}(i)
	}

	wg.Wait()
	wallElapsed := time.Since(wallStart)

	// Aggregate statistics
	stats := &concurrentStats{TotalRequests: totalRequests}
	for _, r := range results {
		stats.Durations = append(stats.Durations, r.Duration)
		if r.Err != nil {
			atomic.AddInt64(&stats.Failures, 1)
		} else {
			atomic.AddInt64(&stats.Successes, 1)
			switch r.Decision {
			case DecisionAllow:
				atomic.AddInt64(&stats.AllowCount, 1)
			case DecisionDeny:
				atomic.AddInt64(&stats.DenyCount, 1)
			case DecisionWarn:
				atomic.AddInt64(&stats.WarnCount, 1)
			}
		}
	}

	min, max, mean, p50, p95, p99 := stats.compute()

	t.Logf("=== CUE Context Pool Stress Test Results ===")
	t.Logf("Total requests:    %d", totalRequests)
	t.Logf("Concurrency:       %d", concurrency)
	t.Logf("Wall time:         %v", wallElapsed)
	t.Logf("Throughput:        %.1f req/s", float64(totalRequests)/wallElapsed.Seconds())
	t.Logf("")
	t.Logf("--- Outcomes ---")
	t.Logf("Successes:         %d", stats.Successes)
	t.Logf("Failures:          %d", stats.Failures)
	t.Logf("Allow decisions:   %d", stats.AllowCount)
	t.Logf("Deny decisions:    %d", stats.DenyCount)
	t.Logf("Warn decisions:    %d", stats.WarnCount)
	t.Logf("")
	t.Logf("--- Latency ---")
	t.Logf("Min:               %v", min)
	t.Logf("Max:               %v", max)
	t.Logf("Mean:              %v", mean)
	t.Logf("P50 (median):      %v", p50)
	t.Logf("P95:               %v", p95)
	t.Logf("P99:               %v", p99)

	// Verify zero failures
	if stats.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", stats.Failures)
		for _, r := range results {
			if r.Err != nil {
				t.Errorf("  request %d: %v", r.RequestID, r.Err)
			}
		}
	}

	// Verify correctness: even requests → allow, odd requests → deny
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if r.RequestID%2 == 0 {
			if r.Decision != DecisionAllow {
				t.Errorf("request %d: expected allow (x=1, name present), got %s", r.RequestID, r.Decision)
			}
		} else {
			if r.Decision != DecisionDeny {
				t.Errorf("request %d: expected deny (x=0, name missing), got %s", r.RequestID, r.Decision)
			}
		}
	}

	// Verify expected distribution: 500 allow, 500 deny
	if stats.AllowCount != 500 {
		t.Errorf("expected 500 allow decisions, got %d", stats.AllowCount)
	}
	if stats.DenyCount != 500 {
		t.Errorf("expected 500 deny decisions, got %d", stats.DenyCount)
	}
}

// TestConcurrentCueContextPool_MixedOperations stress-tests the pool with
// concurrent evaluations, validations, and policy loads happening simultaneously
// to verify the pool handles mixed operation types without corruption.
func TestConcurrentCueContextPool_MixedOperations(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	basePolicy := makePolicy("base", "default", "base policy",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "val", equals: 1}}, message: "fail"}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "base", "default", basePolicy); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	const opsPerType = 200
	var wg sync.WaitGroup
	var evalSuccesses, evalFailures atomic.Int64
	var validateSuccesses, validateFailures atomic.Int64
	var loadSuccesses, loadFailures atomic.Int64

	evalDurations := make([]time.Duration, opsPerType)
	validateDurations := make([]time.Duration, opsPerType)

	// Concurrent evaluations (scoped to "default" namespace so dynamic policy
	// loads into "dynamic" namespace don't affect correctness assertions)
	for i := 0; i < opsPerType; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := time.Now()
			resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
				Input:     map[string]any{"val": float64(idx % 2)},
				Namespace: "default",
			})
			evalDurations[idx] = time.Since(start)
			if err != nil {
				evalFailures.Add(1)
				return
			}
			evalSuccesses.Add(1)
			// Verify correctness
			if idx%2 == 1 {
				if resp.Decision != DecisionAllow {
					t.Errorf("eval %d: expected allow, got %s", idx, resp.Decision)
				}
			} else {
				if resp.Decision != DecisionDeny {
					t.Errorf("eval %d: expected deny, got %s", idx, resp.Decision)
				}
			}
		}(i)
	}

	// Concurrent validations
	for i := 0; i < opsPerType; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			source := fmt.Sprintf(`apiVersion: "policy.garmr.io/v1"
kind: "Policy"
metadata: { name: "val-%d", namespace: "default" }
spec: {
	description: "validation test %d"
	target: resources: [{kind: "*"}]
	rules: [{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}]
	enforcement: action: "deny"
}`, idx, idx)
			start := time.Now()
			errs, _ := eng.Validate(source)
			validateDurations[idx] = time.Since(start)
			if len(errs) > 0 {
				validateFailures.Add(1)
				return
			}
			validateSuccesses.Add(1)
		}(i)
	}

	// Concurrent policy loads (each to a unique name so no lock contention on same key)
	for i := 0; i < opsPerType; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("dyn-%d", idx)
			source := makePolicy(name, "dynamic", fmt.Sprintf("dynamic policy %d", idx),
				`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
				"deny", "")
			if err := eng.LoadPolicy(context.Background(), name, "dynamic", source); err != nil {
				loadFailures.Add(1)
				return
			}
			loadSuccesses.Add(1)
		}(i)
	}

	wg.Wait()

	// Compute eval latency stats
	evalStats := &concurrentStats{Durations: evalDurations}
	eMin, eMax, eMean, eP50, eP95, eP99 := evalStats.compute()

	// Compute validate latency stats
	valStats := &concurrentStats{Durations: validateDurations}
	vMin, vMax, vMean, vP50, vP95, vP99 := valStats.compute()

	t.Logf("=== Mixed Operations Stress Test ===")
	t.Logf("Operations per type: %d (total: %d)", opsPerType, opsPerType*3)
	t.Logf("")
	t.Logf("--- Evaluations ---")
	t.Logf("Successes: %d  Failures: %d", evalSuccesses.Load(), evalFailures.Load())
	t.Logf("Latency  min=%v  max=%v  mean=%v  p50=%v  p95=%v  p99=%v", eMin, eMax, eMean, eP50, eP95, eP99)
	t.Logf("")
	t.Logf("--- Validations ---")
	t.Logf("Successes: %d  Failures: %d", validateSuccesses.Load(), validateFailures.Load())
	t.Logf("Latency  min=%v  max=%v  mean=%v  p50=%v  p95=%v  p99=%v", vMin, vMax, vMean, vP50, vP95, vP99)
	t.Logf("")
	t.Logf("--- Policy Loads ---")
	t.Logf("Successes: %d  Failures: %d", loadSuccesses.Load(), loadFailures.Load())

	// Verify no failures
	if evalFailures.Load() != 0 {
		t.Errorf("expected 0 eval failures, got %d", evalFailures.Load())
	}
	if validateFailures.Load() != 0 {
		t.Errorf("expected 0 validate failures, got %d", validateFailures.Load())
	}
	if loadFailures.Load() != 0 {
		t.Errorf("expected 0 load failures, got %d", loadFailures.Load())
	}

	// Verify all dynamically loaded policies exist
	policies := eng.ListPolicies("dynamic")
	if len(policies) != opsPerType {
		t.Errorf("expected %d dynamic policies, got %d", opsPerType, len(policies))
	}
}

// TestConcurrentCueContextPool_PoolIsolation verifies that CUE contexts from
// the pool are truly isolated — one goroutine's CUE compilation doesn't corrupt
// another goroutine's evaluation. This uses deliberately different policy shapes
// to maximize the chance of detecting cross-context contamination.
func TestConcurrentCueContextPool_PoolIsolation(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Load 5 policies with different rules to maximize schema diversity
	policies := []struct {
		name, rules, action string
		passInput           map[string]any
		failInput           map[string]any
	}{
		{
			name:      "numeric-check",
			rules:     `{id: "r1", description: "x>10", severity: "high", expr: {match: {path: "x", greaterThan: 10}}, message: "x too low"}`,
			action:    "deny",
			passInput: map[string]any{"x": float64(20)},
			failInput: map[string]any{"x": float64(5)},
		},
		{
			name:      "string-check",
			rules:     `{id: "r2", description: "env is prod", severity: "medium", expr: {match: {path: "env", equals: "prod"}}, message: "not prod"}`,
			action:    "deny",
			passInput: map[string]any{"env": "prod"},
			failInput: map[string]any{"env": "dev"},
		},
		{
			name:      "pattern-check",
			rules:     `{id: "r3", description: "name format", severity: "low", expr: {match: {path: "name", pattern: "^svc-[a-z]+$"}}, message: "bad name"}`,
			action:    "deny",
			passInput: map[string]any{"name": "svc-frontend"},
			failInput: map[string]any{"name": "INVALID"},
		},
		{
			name:      "multi-rule",
			rules:     `{id: "r4a", description: "port range", severity: "high", expr: {match: {path: "port", greaterThan: 1023}}, message: "privileged port"}, {id: "r4b", description: "tls required", severity: "high", expr: {match: {path: "tls", equals: true}}, message: "tls off"}`,
			action:    "deny",
			passInput: map[string]any{"port": float64(8080), "tls": true},
			failInput: map[string]any{"port": float64(80), "tls": false},
		},
		{
			name:      "exists-check",
			rules:     `{id: "r5", description: "labels exist", severity: "medium", expr: {exists: {path: "metadata.labels"}}, message: "no labels"}`,
			action:    "warn",
			passInput: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "test"}}},
			failInput: map[string]any{"metadata": map[string]any{}},
		},
	}

	for _, p := range policies {
		source := makePolicy(p.name, "default", p.name,
			p.rules, p.action, "")
		if err := eng.LoadPolicy(context.Background(), p.name, "default", source); err != nil {
			t.Fatalf("LoadPolicy %s: %v", p.name, err)
		}
	}

	const requestsPerPolicy = 200
	totalRequests := len(policies) * requestsPerPolicy * 2 // pass + fail per policy

	type isolationResult struct {
		policyIdx int
		isPass    bool
		decision  Decision
		err       error
		duration  time.Duration
	}

	results := make([]isolationResult, totalRequests)
	var wg sync.WaitGroup

	idx := 0
	for pi, p := range policies {
		for j := 0; j < requestsPerPolicy; j++ {
			// Pass case
			wg.Add(1)
			go func(resIdx, pIdx int, input map[string]any) {
				defer wg.Done()
				start := time.Now()
				resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
				results[resIdx] = isolationResult{
					policyIdx: pIdx,
					isPass:    true,
					err:       err,
					duration:  time.Since(start),
				}
				if resp != nil {
					results[resIdx].decision = resp.Decision
				}
			}(idx, pi, p.passInput)
			idx++

			// Fail case
			wg.Add(1)
			go func(resIdx, pIdx int, input map[string]any) {
				defer wg.Done()
				start := time.Now()
				resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
				results[resIdx] = isolationResult{
					policyIdx: pIdx,
					isPass:    false,
					err:       err,
					duration:  time.Since(start),
				}
				if resp != nil {
					results[resIdx].decision = resp.Decision
				}
			}(idx, pi, p.failInput)
			idx++
		}
	}

	wg.Wait()

	// Aggregate per-policy stats
	type policyStats struct {
		passCorrect, passWrong, failCorrect, failWrong int
		errors                                         int
		durations                                      []time.Duration
	}
	perPolicy := make([]policyStats, len(policies))

	for _, r := range results {
		ps := &perPolicy[r.policyIdx]
		ps.durations = append(ps.durations, r.duration)

		if r.err != nil {
			ps.errors++
			continue
		}

		// All policies evaluate together, so "pass" means all 5 policy rules pass
		// and "fail" means at least one fails. Since we're sending input that
		// satisfies only one policy's rules, the overall decision depends on all policies.
		// The key correctness check: no errors and deterministic decisions for same input.
		if r.isPass {
			// Even pass inputs won't satisfy ALL 5 policies, so we just verify
			// the decision is deterministic and non-error.
			ps.passCorrect++
		} else {
			ps.failCorrect++
		}
	}

	t.Logf("=== Pool Isolation Test Results ===")
	t.Logf("Policies: %d  Requests per policy: %d (pass+fail)  Total: %d",
		len(policies), requestsPerPolicy*2, totalRequests)
	t.Logf("")

	var allDurations []time.Duration
	totalErrors := 0
	for i, ps := range perPolicy {
		allDurations = append(allDurations, ps.durations...)
		totalErrors += ps.errors
		t.Logf("Policy %q: pass=%d fail=%d errors=%d",
			policies[i].name, ps.passCorrect, ps.failCorrect, ps.errors)
	}

	stats := &concurrentStats{Durations: allDurations}
	min, max, mean, p50, p95, p99 := stats.compute()
	t.Logf("")
	t.Logf("--- Aggregate Latency ---")
	t.Logf("Min: %v  Max: %v  Mean: %v", min, max, mean)
	t.Logf("P50: %v  P95: %v  P99: %v", p50, p95, p99)

	if totalErrors != 0 {
		t.Errorf("expected 0 errors across all policies, got %d", totalErrors)
	}

	// Verify determinism: same input should always produce same decision.
	// Group results by (policyIdx, isPass) and check decision consistency.
	type groupKey struct {
		pIdx   int
		isPass bool
	}
	groups := make(map[groupKey]map[Decision]int)
	for _, r := range results {
		if r.err != nil {
			continue
		}
		key := groupKey{r.policyIdx, r.isPass}
		if groups[key] == nil {
			groups[key] = make(map[Decision]int)
		}
		groups[key][r.decision]++
	}

	for key, decisions := range groups {
		if len(decisions) > 1 {
			t.Errorf("NON-DETERMINISTIC: policy %q isPass=%v produced multiple decisions: %v",
				policies[key.pIdx].name, key.isPass, decisions)
		}
	}
}
