package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// targetedPolicy builds a policy with an explicit target selector block.
func targetedPolicy(name, selector, rules string) string {
	return fmt.Sprintf(`
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "%s"
	namespace: "default"
}
spec: {
	description: "targeted"
	target: resources: [%s]
	rules: [%s]
	enforcement: action: "deny"
}
`, name, selector, rules)
}

const alwaysFailRule = `{id: "r1", description: "always fails", severity: "high", expr: {match: {path: "kind", equals: "NoSuchKind"}}}`

func TestTargetSelector_Namespaces(t *testing.T) {
	src := targetedPolicy("ns-scoped", `{kind: "pod", namespaces: ["prod", "team-*"]}`, alwaysFailRule)
	eng := loadTestPolicy(t, "ns-scoped", "default", src)
	eng.SetRequireMatch(false)
	ctx := context.Background()

	cases := []struct {
		namespace string
		want      Decision
	}{
		{"prod", DecisionDeny},     // exact match
		{"team-abc", DecisionDeny}, // glob match
		{"dev", DecisionAllow},     // no match: policy not applicable
	}
	for _, tc := range cases {
		resp, err := eng.Evaluate(ctx, &EvaluateRequest{
			Input: map[string]any{
				"kind":     "Pod",
				"metadata": map[string]any{"name": "web", "namespace": tc.namespace},
			},
		})
		if err != nil {
			t.Fatalf("evaluate failed: %v", err)
		}
		if resp.Decision != tc.want {
			t.Errorf("namespace %q: expected %s, got %s", tc.namespace, tc.want, resp.Decision)
		}
	}
}

func TestTargetSelector_Annotations(t *testing.T) {
	src := targetedPolicy("ann-scoped", `{kind: "pod", annotations: {"team": "platform"}}`, alwaysFailRule)
	eng := loadTestPolicy(t, "ann-scoped", "default", src)
	eng.SetRequireMatch(false)
	ctx := context.Background()

	cases := []struct {
		annotations map[string]any
		want        Decision
	}{
		{map[string]any{"team": "platform"}, DecisionDeny},
		{map[string]any{"team": "web"}, DecisionAllow},
		{nil, DecisionAllow}, // no annotations at all
	}
	for _, tc := range cases {
		input := map[string]any{
			"kind":     "Pod",
			"metadata": map[string]any{"name": "web"},
		}
		if tc.annotations != nil {
			input["metadata"].(map[string]any)["annotations"] = tc.annotations
		}
		resp, err := eng.Evaluate(ctx, &EvaluateRequest{Input: input})
		if err != nil {
			t.Fatalf("evaluate failed: %v", err)
		}
		if resp.Decision != tc.want {
			t.Errorf("annotations %v: expected %s, got %s", tc.annotations, tc.want, resp.Decision)
		}
	}
}

func TestSemver_GarbageFailsClosed(t *testing.T) {
	// Before the fix, "garbage" parsed as 0.0.0 and PASSED lessThan "1.0.0".
	source := makePolicy("semver-garbage", "default", "semver",
		`{id: "r1", description: "version cap", severity: "high", expr: {match: {path: "version", semver: {lessThan: "1.0.0"}}}}`,
		"deny", "")
	eng := loadTestPolicy(t, "semver-garbage", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Release", "version": "garbage"},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for unparseable semver, got %s", resp.Decision)
	}
	if len(resp.Results) == 0 || !strings.Contains(resp.Results[0].Message, "not a valid semver") {
		t.Errorf("expected semver diagnostic, got %+v", resp.Results)
	}
}

func TestCompare_SemverGarbageFailsClosed(t *testing.T) {
	source := makePolicy("cmp-semver", "default", "compare semver",
		`{id: "r1", description: "version check", severity: "high", expr: {compare: {
			left: {path: "version"}
			op: "semverGte"
			right: {literal: "1.0.0"}
		}}}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-semver", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Release", "version": "not-a-version"},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for garbage semver operand, got %s", resp.Decision)
	}
}

func TestCompare_DatetimeGarbageFailsClosed(t *testing.T) {
	// Before the fix, an unparseable datetime compared as "equal", so
	// afterOrEqual PASSED (fail-open).
	source := makePolicy("cmp-dt", "default", "compare datetime",
		`{id: "r1", description: "date check", severity: "high", expr: {compare: {
			left: {path: "deployedAt"}
			op: "afterOrEqual"
			right: {literal: "2024-01-01T00:00:00Z"}
		}}}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-dt", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Release", "deployedAt": "not-a-date"},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for garbage datetime operand, got %s", resp.Decision)
	}
}

func TestCompare_NonNumericFailsClosed(t *testing.T) {
	source := makePolicy("cmp-num", "default", "compare numeric",
		`{id: "r1", description: "replica floor", severity: "high", expr: {compare: {
			left: {path: "replicas"}
			op: ">"
			right: {literal: 5}
		}}}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-num", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Deployment", "replicas": "abc"},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for non-numeric operand, got %s", resp.Decision)
	}
	if len(resp.Results) == 0 || !strings.Contains(resp.Results[0].Message, "non-numeric operand") {
		t.Errorf("expected non-numeric diagnostic, got %+v", resp.Results)
	}
}

func TestRef_RejectedAtCompileTime(t *testing.T) {
	source := makePolicy("ref-pol", "default", "ref",
		`{id: "r1", description: "cross-policy ref", severity: "high", expr: {ref: "other-policy"}}`,
		"deny", "")
	eng := newTestEngine(t)
	err := eng.LoadPolicy(context.Background(), "ref-pol", "default", source)
	if err == nil || !strings.Contains(err.Error(), "field not allowed") {
		t.Errorf("expected load-time rejection of 'ref', got %v", err)
	}
}

func TestRef_NestedRejectedAtLoad(t *testing.T) {
	// Expressions are typed all the way down, so a ref nested inside
	// any/all is rejected at load like a top-level one.
	source := makePolicy("ref-nested", "default", "nested ref",
		`{id: "r1", description: "nested ref", severity: "high", expr: {any: [{ref: "other-policy"}]}}`,
		"deny", "")
	eng := newTestEngine(t)
	if err := eng.LoadPolicy(context.Background(), "ref-nested", "default", source); err == nil {
		t.Error("expected load-time rejection of a nested 'ref'")
	}
}

func TestRequires_RejectedBySchema(t *testing.T) {
	// spec.requires was removed from the schema; a policy declaring it must
	// fail schema validation at load time.
	source := makePolicy("requires-pol", "default", "requires",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "kind", equals: "Pod"}}}`,
		"deny", `requires: ["other-policy"]`)
	eng := newTestEngine(t)
	err := eng.LoadPolicy(context.Background(), "requires-pol", "default", source)
	if err == nil {
		t.Error("expected schema rejection of spec.requires")
	}
}

func TestEvaluate_MaxRulesCap(t *testing.T) {
	rules := `
		{id: "r1", description: "one", severity: "low", expr: {match: {path: "kind", equals: "Pod"}}},
		{id: "r2", description: "two", severity: "low", expr: {match: {path: "kind", equals: "Pod"}}},
		{id: "r3", description: "three", severity: "low", expr: {match: {path: "kind", equals: "Pod"}}}`
	source := makePolicy("max-rules", "default", "cap", rules, "deny", "evaluation: {maxRules: 2}")
	eng := loadTestPolicy(t, "max-rules", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Pod"},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Metrics.RulesEvaluated != 2 {
		t.Errorf("expected 2 rules evaluated with maxRules=2, got %d", resp.Metrics.RulesEvaluated)
	}
	if resp.Summary.TotalRules != 2 {
		t.Errorf("expected Summary.TotalRules=2 (capped), got %d", resp.Summary.TotalRules)
	}
}

func TestEvaluate_SummaryPopulated(t *testing.T) {
	rules := `
		{id: "r1", description: "passes", severity: "low", category: "quality", expr: {match: {path: "kind", equals: "Pod"}}},
		{id: "r2", description: "fails", severity: "high", category: "security", expr: {match: {path: "kind", equals: "NoSuchKind"}}}`
	source := makePolicy("summary-pol", "default", "summary", rules, "deny", "")
	eng := loadTestPolicy(t, "summary-pol", "default", source)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Pod"},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	s := resp.Summary
	if s.TotalRules != 2 || s.Passed != 1 || s.Failed != 1 || s.Skipped != 0 {
		t.Errorf("summary counts wrong: %+v", s)
	}
}

func TestEvaluate_FailFastSkipCountExcludesFiltered(t *testing.T) {
	// Two policies: the first fail-fasts on its first rule; the second has
	// one in-scope rule and one filtered-out rule. RulesSkipped must count
	// only genuinely skipped in-scope rules, not category-filtered ones.
	eng := newTestEngine(t)
	ctx := context.Background()

	first := makePolicy("a-failfast", "default", "ff",
		`{id: "f1", description: "fails", severity: "high", expr: {match: {path: "kind", equals: "NoSuchKind"}}},
		 {id: "f2", description: "never reached", severity: "low", expr: {match: {path: "kind", equals: "Pod"}}}`,
		"deny", "evaluation: {failFast: true}")
	if err := eng.LoadPolicy(ctx, "a-failfast", "default", first); err != nil {
		t.Fatalf("loading first: %v", err)
	}

	second := makePolicy("b-filtered", "default", "filters",
		`{id: "s1", description: "in scope", severity: "low", category: "quality", expr: {match: {path: "kind", equals: "Pod"}}},
		 {id: "s2", description: "filtered out", severity: "low", category: "excluded", expr: {match: {path: "kind", equals: "Pod"}}}`,
		"deny", `evaluation: {excludeCategories: ["excluded"]}`)
	if err := eng.LoadPolicy(ctx, "b-filtered", "default", second); err != nil {
		t.Fatalf("loading second: %v", err)
	}

	resp, err := eng.Evaluate(ctx, &EvaluateRequest{Input: map[string]any{"kind": "Pod"}})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if !resp.TerminatedEarly {
		t.Fatal("expected fail-fast termination")
	}
	// In scope: f1, f2 (policy 1) + s1 (policy 2, s2 filtered) = 3.
	// Evaluated: f1 only. Skipped: f2 + s1 = 2 (not 3).
	if resp.EvaluationMode.TotalRulesInScope != 3 {
		t.Errorf("expected 3 rules in scope, got %d", resp.EvaluationMode.TotalRulesInScope)
	}
	if resp.EvaluationMode.RulesSkipped != 2 {
		t.Errorf("expected 2 rules skipped, got %d", resp.EvaluationMode.RulesSkipped)
	}
}
