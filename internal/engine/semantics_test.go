package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// decide loads a one-rule policy and evaluates input against it.
func decide(t *testing.T, expr string, input map[string]any) *EvaluateResponse {
	t.Helper()
	rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "high", expr: %s}`, expr)
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return resp
}

// An operand of the wrong type is an evaluation error, and an error fails
// the rule even under `not` or `any`. These all used to PASS: `not` inverted
// any failure, including "this check could not run".
func TestErrorsAreNotInvertedByNot(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		input map[string]any
	}{
		{"numeric operator on a string", `{not: {match: {path: "replicas", greaterThan: 3}}}`, map[string]any{"replicas": "lots"}},
		{"garbage datetime", `{not: {match: {path: "notAfter", datetime: {before: "2020-01-01"}}}}`, map[string]any{"notAfter": "garbage"}},
		{"garbage semver", `{not: {match: {path: "v", semver: {lessThan: "1.0.0"}}}}`, map[string]any{"v": "not-a-version"}},
		{"pattern on a number", `{not: {match: {path: "name", pattern: "^x"}}}`, map[string]any{"name": 7.0}},
		{"builtin error", `{not: {func: {name: "base64Decode", args: [{path: "s"}]}}}`, map[string]any{"s": "%%%"}},
		{"error inside any", `{any: [{match: {path: "replicas", greaterThan: 3}}]}`, map[string]any{"replicas": "lots"}},
		{"forEach over a non-list", `{not: {forEach: {path: "items", condition: {match: {path: "item", equals: 1}}}}}`, map[string]any{"items": "nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := decide(t, tt.expr, tt.input)
			if resp.Decision != DecisionDeny {
				t.Fatalf("decision = %s, want deny: an evaluation error must fail the rule", resp.Decision)
			}
			if msg := resp.Results[0].Message; !strings.Contains(msg, "could not be evaluated") {
				t.Errorf("message = %q, want it to say the rule could not be evaluated", msg)
			}
		})
	}
}

// A missing field is a plain failure, so `not` of a check on an absent
// field passes — container-security's "must not be privileged" relies on it.
func TestMissingFieldUnderNotPasses(t *testing.T) {
	resp := decide(t, `{not: {match: {path: "securityContext.privileged", equals: true}}}`, map[string]any{})
	if resp.Decision != DecisionAllow {
		t.Errorf("decision = %s, want allow", resp.Decision)
	}
}

// `all` fails when any branch fails, even if an earlier branch errored: under
// three-valued logic the failure decides the conjunction.
func TestKleeneConnectives(t *testing.T) {
	input := map[string]any{"n": "x", "m": 1.0}
	// not(all(error, fail)) = not(fail) = pass
	if d := decide(t, `{not: {all: [{match: {path: "n", greaterThan: 1}}, {match: {path: "m", equals: 2}}]}}`, input).Decision; d != DecisionAllow {
		t.Errorf("not(all(error, fail)) = %s, want allow", d)
	}
	// any(error, pass) = pass
	if d := decide(t, `{any: [{match: {path: "n", greaterThan: 1}}, {match: {path: "m", equals: 1}}]}`, input).Decision; d != DecisionAllow {
		t.Errorf("any(error, pass) = %s, want allow", d)
	}
}

// Equality is JSON-typed: a string never equals a number or a bool.
func TestStrictEqualityInRules(t *testing.T) {
	tests := []struct {
		expr  string
		input map[string]any
		want  Decision
	}{
		{`{match: {path: "v", equals: 1}}`, map[string]any{"v": "1"}, DecisionDeny},
		{`{match: {path: "v", equals: 1}}`, map[string]any{"v": 1.0}, DecisionAllow},
		{`{match: {path: "v", equals: true}}`, map[string]any{"v": "true"}, DecisionDeny},
		{`{match: {path: "v", in: ["1", "2"]}}`, map[string]any{"v": 1.0}, DecisionDeny},
		{`{match: {path: "v", notIn: [0]}}`, map[string]any{"v": "0"}, DecisionAllow},
		{`{compare: {left: {path: "v"}, op: "==", right: {literal: "<nil>"}}}`, map[string]any{"v": nil}, DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			if got := decide(t, tt.expr, tt.input).Decision; got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}
}

// notIn against something that is not a list (for example a missing path,
// which resolves to null) used to pass for every value.
func TestCompareNotInNeedsAList(t *testing.T) {
	resp := decide(t, `{compare: {left: {path: "region"}, op: "notIn", right: {path: "blocked"}}}`, map[string]any{"region": "us-east-1"})
	if resp.Decision != DecisionDeny {
		t.Errorf("decision = %s, want deny", resp.Decision)
	}
}

// compare contains: a list contains an element; strings use substrings. It
// used to stringify a list with %v and substring-match the rendering.
func TestCompareContainsOnLists(t *testing.T) {
	if d := decide(t, `{compare: {left: {path: "tags"}, op: "contains", right: {literal: "a b"}}}`,
		map[string]any{"tags": []any{"a", "b"}}).Decision; d != DecisionDeny {
		t.Errorf("list contains %q = %s, want deny", "a b", d)
	}
	if d := decide(t, `{compare: {left: {path: "tags"}, op: "contains", right: {literal: "b"}}}`,
		map[string]any{"tags": []any{"a", "b"}}).Decision; d != DecisionAllow {
		t.Errorf("list contains element = %s, want allow", d)
	}
}

// Paths used to go through cue.ParsePath, which did not resolve keys that
// are not CUE identifiers. `exists: false` then passed on a field that was
// present.
func TestPathSyntax(t *testing.T) {
	input := map[string]any{
		"spec": map[string]any{
			"host-network": true,
			"_private":     "x",
			"containers":   []any{map[string]any{"image": "nginx"}},
		},
		"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/name": "web"}},
	}
	tests := []struct {
		expr string
		want Decision
	}{
		{`{match: {path: "spec.host-network", exists: false}}`, DecisionDeny},
		{`{match: {path: "spec.host-network", equals: true}}`, DecisionAllow},
		{`{match: {path: "spec._private", equals: "x"}}`, DecisionAllow},
		{`{match: {path: "metadata.labels.\"app.kubernetes.io/name\"", equals: "web"}}`, DecisionAllow},
		{`{match: {path: "spec.containers[0].image", equals: "nginx"}}`, DecisionAllow},
		{`{match: {path: "spec.containers[1].image", exists: true}}`, DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			if got := decide(t, tt.expr, input).Decision; got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParsePath_Errors(t *testing.T) {
	for _, p := range []string{"", ".a", "a.", "a..b", "a[x]", "a[-1]", `a."unterminated`, "a[0", "a]b"} {
		if _, err := parsePath(p); err == nil {
			t.Errorf("parsePath(%q) succeeded, want an error", p)
		}
	}
}

// forEach binds the element under its alias, which shadows an input field
// of the same name, and `_index` is the element's position.
func TestForEachScoping(t *testing.T) {
	input := map[string]any{
		"item":  "shadowed",
		"items": []any{map[string]any{"v": 0.0}, map[string]any{"v": 1.0}},
		"want":  []any{0.0, 1.0},
	}
	if d := decide(t, `{forEach: {path: "items", condition: {compare: {left: {path: "item.v"}, op: "==", right: {path: "_index"}}}}}`, input).Decision; d != DecisionAllow {
		t.Errorf("_index comparison = %s, want allow", d)
	}

	// Nested forEach: the inner alias is visible alongside the outer one.
	nested := map[string]any{
		"groups": []any{
			map[string]any{"name": "a", "members": []any{map[string]any{"group": "a"}}},
			map[string]any{"name": "b", "members": []any{map[string]any{"group": "a"}}},
		},
	}
	expr := `{forEach: {path: "groups", as: "g", condition: {forEach: {path: "g.members", as: "m", condition: {compare: {left: {path: "m.group"}, op: "==", right: {path: "g.name"}}}}}}}`
	resp := decide(t, expr, nested)
	if resp.Decision != DecisionDeny {
		t.Fatalf("nested forEach = %s, want deny (group b has a member of a)", resp.Decision)
	}
	if !strings.Contains(resp.Results[0].Message, "groups[1]") {
		t.Errorf("message = %q, want it to point at groups[1]", resp.Results[0].Message)
	}
}

// The evaluation deadline is honoured inside a forEach, not only between
// rules: a large list is the construct whose cost the caller controls.
func TestForEachHonoursDeadline(t *testing.T) {
	items := make([]any, 200000)
	for i := range items {
		items[i] = map[string]any{"name": "x"}
	}
	rule := `{id: "r1", description: "d", severity: "high", expr: {forEach: {path: "items", condition: {match: {path: "item.name", pattern: "^x$"}}}}}`
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", `evaluation: timeout: "1ms"`))

	start := time.Now()
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"items": items}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("decision = %s, want deny on timeout", resp.Decision)
	}
	if len(resp.Results) != 1 || resp.Results[0].RuleID != RuleIDTimeout {
		t.Errorf("results = %+v, want the single timeout result", resp.Results)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("evaluation took %s; the deadline was not enforced inside forEach", elapsed)
	}
}

// String length counts characters, not bytes.
func TestLengthCountsRunes(t *testing.T) {
	if d := decide(t, `{match: {path: "s", length: {lessThanOrEqual: 3}}}`, map[string]any{"s": "héé"}).Decision; d != DecisionAllow {
		t.Errorf("decision = %s, want allow for a 3-character string", d)
	}
}

// Typed Go input (as from library callers) is normalized, not silently
// treated as missing.
func TestTypedGoInputIsNormalized(t *testing.T) {
	input := map[string]any{
		"tags":   []string{"a", "b"},
		"labels": map[string]string{"team": "x"},
	}
	if d := decide(t, `{match: {path: "tags", containsAll: ["a"]}}`, input).Decision; d != DecisionAllow {
		t.Errorf("[]string containsAll = %s, want allow", d)
	}
	if d := decide(t, `{match: {path: "labels.team", exists: false}}`, input).Decision; d != DecisionDeny {
		t.Errorf("map[string]string exists:false = %s, want deny", d)
	}
}
