package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// decideRule loads a one-rule policy (expr and message) and evaluates input.
func decideRule(t *testing.T, expr, message string, input map[string]any) *EvaluateResponse {
	t.Helper()
	rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "high", expr: %s, message: %q}`, expr, message)
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.Decision != DecisionAllow && len(resp.Results) == 0 {
		t.Fatalf("decision %s with no results", resp.Decision)
	}
	return resp
}

// msgOf returns the first result's message, or "" when there is none.
func msgOf(r *EvaluateResponse) string {
	if len(r.Results) == 0 {
		return ""
	}
	return r.Results[0].Message
}

func pod(containers ...map[string]any) map[string]any {
	list := make([]any, len(containers))
	for i, c := range containers {
		list[i] = c
	}
	return map[string]any{"kind": "Pod", "metadata": map[string]any{"name": "web-pod"}, "spec": map[string]any{"containers": list}}
}

// Example 1: a join whose message names the offending elements.
func TestMessage_NamesFailingForEachElements(t *testing.T) {
	expr := `{forEach: {path: "spec.containers", as: "c", condition: {forEach: {path: "c.ports", as: "p",
		condition: {compare: {left: {path: "p.containerPort"}, op: "in", right: {path: "spec.declaredPorts"}}}}}}}`
	input := pod(
		map[string]any{"name": "web", "ports": []any{map[string]any{"containerPort": 80.0}}},
		map[string]any{"name": "debug", "ports": []any{map[string]any{"containerPort": 9229.0}, map[string]any{"containerPort": 6060.0}}},
	)
	input["spec"].(map[string]any)["declaredPorts"] = []any{80.0, 443.0}

	resp := decideRule(t, expr, "container {{c.name}} exposes undeclared port {{p.containerPort}} (#{{_index}})", input)
	if resp.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want deny", resp.Decision)
	}
	want := "container debug exposes undeclared port 9229 (#0); container debug exposes undeclared port 6060 (#1)"
	if got := msgOf(resp); got != want {
		t.Errorf("message = %q\nwant      %q", got, want)
	}
}

// A message can also read the input directly, and leaves an unresolvable
// placeholder as written.
func TestMessage_InputPathsAndUnresolved(t *testing.T) {
	resp := decideRule(t, `{match: {path: "spec.replicas", greaterThan: 1}}`,
		"{{metadata.name}} has {{spec.replicas}} replica(s); {{spec.missing}} {{.nope}}",
		map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"replicas": 1.0}})
	if got, want := msgOf(resp), "web has 1 replica(s); {{spec.missing}} {{.nope}}"; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}
}

// Failures inside a branch that ended up passing (any, not) are not
// reported, even when another check in the rule fails.
func TestMessage_DropsFailuresFromPassingBranches(t *testing.T) {
	expr := `{all: [
		{any: [{forEach: {path: "spec.containers", as: "c", condition: {match: {path: "c.name", equals: "zzz"}}}},
		       {match: {path: "metadata.name", exists: true}}]},
		{not: {forEach: {path: "spec.containers", as: "c", condition: {match: {path: "c.name", equals: "zzz"}}}}},
		{forEach: {path: "spec.containers", as: "c", condition: {match: {path: "c.name", hasPrefix: "ok"}}}}]}`
	input := pod(map[string]any{"name": "ok-1"}, map[string]any{"name": "bad"})
	if got := msgOf(decideRule(t, expr, "{{c.name}}", input)); got != "bad" {
		t.Errorf("message = %q, want only the element of the check that failed (bad)", got)
	}
}

func TestMessage_InvalidPlaceholderRejectedAtLoad(t *testing.T) {
	for _, msg := range []string{"{{a..b}}", "unterminated {{a"} {
		rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "high", expr: {match: {path: "a", exists: true}}, message: %q}`, msg)
		err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
		if err == nil {
			t.Errorf("message %q loaded; it must be rejected", msg)
		}
	}
}

// Example 2: aggregate over a projection.
func TestProjection_Aggregates(t *testing.T) {
	expr := `{compare: {left: {func: {name: "sum", args: [{path: "spec.containers[*].cpu"}]}}, op: "<=", right: {literal: 4}}}`

	if d := decideRule(t, expr, "", pod(map[string]any{"cpu": 1.0}, map[string]any{"cpu": 2.5})).Decision; d != DecisionAllow {
		t.Errorf("total 3.5 = %s, want allow", d)
	}
	if d := decideRule(t, expr, "", pod(map[string]any{"cpu": 3.0}, map[string]any{"cpu": 2.0})).Decision; d != DecisionDeny {
		t.Errorf("total 5 = %s, want deny", d)
	}
	// A container without cpu contributes null: the sum cannot be computed,
	// so the rule fails rather than under-counting.
	resp := decideRule(t, expr, "", pod(map[string]any{"cpu": 1.0}, map[string]any{}))
	if resp.Decision != DecisionDeny || !strings.Contains(msgOf(resp), "could not be evaluated") {
		t.Errorf("missing cpu: decision %s, message %q; want an evaluation error", resp.Decision, msgOf(resp))
	}
}

func TestProjection_WithMatchAndForEach(t *testing.T) {
	containers := pod(
		map[string]any{"name": "a", "image": "x", "ports": []any{map[string]any{"containerPort": 80.0}}},
		map[string]any{"name": "b", "image": "x", "ports": []any{map[string]any{"containerPort": 80.0}}},
		map[string]any{"name": "c"},
	)
	tests := []struct {
		expr string
		want Decision
	}{
		{`{match: {path: "spec.containers[*].name", unique: true}}`, DecisionAllow},
		{`{match: {path: "spec.containers[*].image", unique: true}}`, DecisionDeny},
		// Nested projections flatten; c has no ports and contributes nothing.
		{`{match: {path: "spec.containers[*].ports[*].containerPort", length: {equals: 2}}}`, DecisionAllow},
		{`{match: {path: "spec.containers[*].ports[*].containerPort", unique: true}}`, DecisionDeny},
		{`{match: {path: "spec.containers[*].name", containsAll: ["a", "c"]}}`, DecisionAllow},
		{`{forEach: {path: "spec.containers[*].name", as: "n", condition: {match: {path: "n", pattern: "^[a-c]$"}}}}`, DecisionAllow},
		{`{match: {path: "spec.nothing[*].x", exists: true}}`, DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			if got := decideRule(t, tt.expr, "", containers).Decision; got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}
}

// Example 3: counting matches.
func TestForEachCount(t *testing.T) {
	expr := `{forEach: {path: "spec.containers", as: "c", count: {lessThanOrEqual: 1},
		condition: {match: {path: "c.securityContext.privileged", equals: true}}}}`
	priv := map[string]any{"securityContext": map[string]any{"privileged": true}}
	plain := map[string]any{}

	if d := decideRule(t, expr, "", pod(priv, plain, plain)).Decision; d != DecisionAllow {
		t.Errorf("one privileged = %s, want allow", d)
	}
	resp := decideRule(t, expr, "{{.count}} privileged containers in {{metadata.name}}", pod(priv, priv, plain))
	if resp.Decision != DecisionDeny {
		t.Fatalf("two privileged = %s, want deny", resp.Decision)
	}
	if got := msgOf(resp); got != "2 privileged containers in web-pod" {
		t.Errorf("message = %q", got)
	}
	// An empty list counts 0.
	atLeast := `{forEach: {path: "spec.containers", count: {greaterThanOrEqual: 1}, condition: {match: {path: "item.name", exists: true}}}}`
	if d := decideRule(t, atLeast, "", pod()).Decision; d != DecisionDeny {
		t.Errorf("empty list with count >= 1 = %s, want deny", d)
	}
	// An element that cannot be evaluated makes the count unknown.
	numeric := `{forEach: {path: "spec.containers", count: {lessThanOrEqual: 5}, condition: {match: {path: "item.cpu", greaterThan: 1}}}}`
	resp = decideRule(t, numeric, "", pod(map[string]any{"cpu": "lots"}))
	if resp.Decision != DecisionDeny || !strings.Contains(msgOf(resp), "could not be evaluated") {
		t.Errorf("errored element: decision %s, message %q; want an evaluation error", resp.Decision, msgOf(resp))
	}
}

func TestForEachCount_ConflictsRejectedAtLoad(t *testing.T) {
	for _, extra := range []string{`mode: "any"`, `allowEmpty: false`} {
		expr := `{forEach: {path: "xs", ` + extra + `, count: {equals: 1}, condition: {match: {path: "item", equals: 1}}}}`
		rule := `{id: "r1", description: "d", severity: "high", expr: ` + expr + `}`
		if err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", makePolicy("p", "default", "d", rule, "deny", "")); err == nil {
			t.Errorf("count with %s loaded; it must be rejected", extra)
		}
	}
}

// Example 4: a join that checks a label selector against labels.
func TestCompareSubsetOf(t *testing.T) {
	expr := `{forEach: {path: "services", as: "s", condition: {forEach: {path: "deployments", as: "d", condition: {any: [
		{compare: {left: {path: "s.metadata.name"}, op: "!=", right: {path: "d.metadata.name"}}},
		{compare: {left: {path: "s.spec.selector"}, op: "subsetOf", right: {path: "d.spec.template.metadata.labels"}}}]}}}}}`
	bundle := func(selector map[string]any) map[string]any {
		return map[string]any{
			"services": []any{map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"selector": selector}}},
			"deployments": []any{
				map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "web", "tier": "fe"}}}}},
				map[string]any{"metadata": map[string]any{"name": "db"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "db"}}}}},
			},
		}
	}
	if d := decideRule(t, expr, "", bundle(map[string]any{"app": "web"})).Decision; d != DecisionAllow {
		t.Errorf("selector within labels = %s, want allow", d)
	}
	resp := decideRule(t, expr, "service {{s.metadata.name}} does not select deployment {{d.metadata.name}}", bundle(map[string]any{"app": "api"}))
	if resp.Decision != DecisionDeny {
		t.Fatalf("selector not within labels = %s, want deny", resp.Decision)
	}
	if got := msgOf(resp); got != "service web does not select deployment web" {
		t.Errorf("message = %q", got)
	}

	tests := []struct {
		expr  string
		input map[string]any
		want  Decision
	}{
		{`{compare: {left: {literal: ["a", "b"]}, op: "subsetOf", right: {path: "xs"}}}`, map[string]any{"xs": []any{"b", "c", "a"}}, DecisionAllow},
		{`{compare: {left: {literal: ["a", "d"]}, op: "subsetOf", right: {path: "xs"}}}`, map[string]any{"xs": []any{"a"}}, DecisionDeny},
		{`{compare: {left: {literal: {}}, op: "subsetOf", right: {path: "m"}}}`, map[string]any{"m": map[string]any{"k": 1.0}}, DecisionAllow},
		{`{compare: {left: {literal: {k: "1"}}, op: "subsetOf", right: {path: "m"}}}`, map[string]any{"m": map[string]any{"k": 1.0}}, DecisionDeny},
		{`{compare: {left: {literal: {k: 1}}, op: "subsetOf", right: {path: "m"}}}`, map[string]any{"m": []any{1.0}}, DecisionDeny},
	}
	for _, tt := range tests {
		if got := decideRule(t, tt.expr, "", tt.input).Decision; got != tt.want {
			t.Errorf("%s = %s, want %s", tt.expr, got, tt.want)
		}
	}
}
