package engine

import (
	"context"
	"fmt"
	"testing"
)

func decideWhen(t *testing.T, when, expr string, input map[string]any) *EvaluateResponse {
	t.Helper()
	rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "high", when: %s, expr: %s, message: "{{metadata.name}} needs 2 replicas"}`, when, expr)
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input, Options: EvaluateOptions{IncludePassed: true}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return resp
}

func TestRuleWhen(t *testing.T) {
	when := `{match: {path: "metadata.labels.env", equals: "prod"}}`
	expr := `{match: {path: "spec.replicas", greaterThanOrEqual: 2}}`
	deploy := func(env any, replicas float64) map[string]any {
		labels := map[string]any{}
		if env != nil {
			labels["env"] = env
		}
		return map[string]any{"metadata": map[string]any{"name": "web", "labels": labels}, "spec": map[string]any{"replicas": replicas}}
	}

	tests := []struct {
		name  string
		input map[string]any
		want  Decision
		msg   string
	}{
		{"applies and holds", deploy("prod", 3), DecisionAllow, ""},
		{"applies and fails", deploy("prod", 1), DecisionDeny, "web needs 2 replicas"},
		{"does not apply", deploy("dev", 1), DecisionAllow, ""},
		{"guard field missing", deploy(nil, 1), DecisionAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := decideWhen(t, when, expr, tt.input)
			if resp.Decision != tt.want {
				t.Fatalf("decision = %s, want %s", resp.Decision, tt.want)
			}
			if len(resp.Results) != 1 {
				t.Fatalf("results = %d, want 1 (a non-applicable rule is reported as passed)", len(resp.Results))
			}
			if got := resp.Results[0].Message; got != tt.msg {
				t.Errorf("message = %q, want %q", got, tt.msg)
			}
		})
	}

	// A guard that cannot be evaluated never skips the check.
	resp := decideWhen(t, `{match: {path: "metadata.labels.env", greaterThan: 1}}`, expr, deploy("prod", 5))
	if resp.Decision != DecisionDeny || msgOf(resp) == "" {
		t.Errorf("erroring guard: decision %s, message %q; want deny with an evaluation error", resp.Decision, msgOf(resp))
	}
}

func TestForEachWhere(t *testing.T) {
	ctr := func(name string, privileged bool) map[string]any {
		return map[string]any{"name": name, "securityContext": map[string]any{"privileged": privileged}}
	}
	input := pod(ctr("app-1", false), ctr("sidecar-istio", true), ctr("app-2", true))

	tests := []struct {
		name string
		expr string
		want Decision
	}{
		{"all over selected", `{forEach: {path: "spec.containers", as: "c", where: {match: {path: "c.name", hasPrefix: "app-"}},
			condition: {match: {path: "c.securityContext.privileged", equals: false}}}}`, DecisionDeny},
		{"skipped elements are not checked", `{forEach: {path: "spec.containers", as: "c", where: {match: {path: "c.name", hasPrefix: "sidecar"}},
			condition: {match: {path: "c.securityContext.privileged", equals: true}}}}`, DecisionAllow},
		{"count over selected", `{forEach: {path: "spec.containers", as: "c", where: {match: {path: "c.name", hasPrefix: "app-"}}, count: {equals: 1},
			condition: {match: {path: "c.securityContext.privileged", equals: true}}}}`, DecisionAllow},
		{"any over selected", `{forEach: {path: "spec.containers", as: "c", mode: "any", where: {match: {path: "c.name", hasPrefix: "sidecar"}},
			condition: {match: {path: "c.securityContext.privileged", equals: false}}}}`, DecisionDeny},
		{"nothing selected passes by default", `{forEach: {path: "spec.containers", as: "c", where: {match: {path: "c.name", equals: "none"}},
			condition: {match: {path: "c.name", equals: "x"}}}}`, DecisionAllow},
		{"nothing selected with allowEmpty false", `{forEach: {path: "spec.containers", as: "c", allowEmpty: false, where: {match: {path: "c.name", equals: "none"}},
			condition: {match: {path: "c.name", equals: "x"}}}}`, DecisionDeny},
		{"where that cannot be evaluated", `{forEach: {path: "spec.containers", as: "c", where: {match: {path: "c.name", greaterThan: 1}},
			condition: {match: {path: "c.name", exists: true}}}}`, DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decideRule(t, tt.expr, "", input).Decision; got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}

	// Messages name only selected, failing elements.
	resp := decideRule(t, `{forEach: {path: "spec.containers", as: "c", where: {match: {path: "c.name", hasPrefix: "app-"}},
		condition: {match: {path: "c.securityContext.privileged", equals: false}}}}`, "{{c.name}} is privileged", input)
	if got := msgOf(resp); got != "app-2 is privileged" {
		t.Errorf("message = %q, want %q", got, "app-2 is privileged")
	}
}

// The join from the readability comparison, written with where.
func TestForEachWhere_Join(t *testing.T) {
	expr := `{forEach: {path: "services", as: "s", condition: {forEach: {
		path: "deployments", as: "d"
		where: {compare: {left: {path: "d.metadata.name"}, op: "==", right: {path: "s.metadata.name"}}}
		condition: {compare: {left: {path: "s.spec.selector"}, op: "subsetOf", right: {path: "d.spec.template.metadata.labels"}}}}}}}`
	input := map[string]any{
		"services": []any{
			map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"selector": map[string]any{"app": "web"}}},
			map[string]any{"metadata": map[string]any{"name": "db"}, "spec": map[string]any{"selector": map[string]any{"app": "postgres"}}},
		},
		"deployments": []any{
			map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "web"}}}}},
			map[string]any{"metadata": map[string]any{"name": "db"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "db"}}}}},
		},
	}
	resp := decideRule(t, expr, "service {{s.metadata.name}} does not select deployment {{d.metadata.name}}", input)
	if resp.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want deny", resp.Decision)
	}
	if got := msgOf(resp); got != "service db does not select deployment db" {
		t.Errorf("message = %q", got)
	}
}

func TestWhereAndWhen_RejectedWhenMalformed(t *testing.T) {
	for _, rule := range []string{
		`{id: "r1", description: "d", severity: "high", when: {mach: {path: "a"}}, expr: {match: {path: "a", exists: true}}}`,
		`{id: "r1", description: "d", severity: "high", expr: {forEach: {path: "xs", where: {match: {path: "item"}}, condition: {match: {path: "item", exists: true}}}}}`,
	} {
		if err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", makePolicy("p", "default", "d", rule, "deny", "")); err == nil {
			t.Errorf("malformed guard loaded: %s", rule)
		}
	}
}
