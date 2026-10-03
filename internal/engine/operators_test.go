package engine

import (
	"context"
	"strings"
	"testing"
)

// Table-driven coverage of the operator surface: every compare operator and
// the semver/datetime/length families, each with a passing and a failing
// input.
func TestOperators(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		input map[string]any
		want  Decision
	}{
		{"!= pass", `{compare: {left: {path: "a"}, op: "!=", right: {literal: 1}}}`, map[string]any{"a": 2.0}, DecisionAllow},
		{"!= fail", `{compare: {left: {path: "a"}, op: "!=", right: {literal: 1}}}`, map[string]any{"a": 1.0}, DecisionDeny},
		{"< strings", `{compare: {left: {path: "a"}, op: "<", right: {literal: "b"}}}`, map[string]any{"a": "a"}, DecisionAllow},
		{"<= numbers", `{compare: {left: {path: "a"}, op: "<=", right: {literal: 1}}}`, map[string]any{"a": 2.0}, DecisionDeny},
		{"in list", `{compare: {left: {path: "a"}, op: "in", right: {literal: ["x", "y"]}}}`, map[string]any{"a": "y"}, DecisionAllow},
		{"notIn list", `{compare: {left: {path: "a"}, op: "notIn", right: {literal: ["x", "y"]}}}`, map[string]any{"a": "y"}, DecisionDeny},
		{"contains substring", `{compare: {left: {path: "a"}, op: "contains", right: {literal: "ell"}}}`, map[string]any{"a": "hello"}, DecisionAllow},
		{"contains non-string", `{compare: {left: {path: "a"}, op: "contains", right: {literal: "x"}}}`, map[string]any{"a": 5.0}, DecisionDeny},
		{"hasPrefix", `{compare: {left: {path: "a"}, op: "hasPrefix", right: {literal: "he"}}}`, map[string]any{"a": "hello"}, DecisionAllow},
		{"hasSuffix", `{compare: {left: {path: "a"}, op: "hasSuffix", right: {literal: "lo"}}}`, map[string]any{"a": "help"}, DecisionDeny},
		{"matches literal", `{compare: {left: {path: "a"}, op: "matches", right: {literal: "^h.*o$"}}}`, map[string]any{"a": "hello"}, DecisionAllow},
		{"matches from input", `{compare: {left: {path: "a"}, op: "matches", right: {path: "re"}}}`, map[string]any{"a": "hello", "re": "^x"}, DecisionDeny},
		{"matches bad input pattern", `{compare: {left: {path: "a"}, op: "matches", right: {path: "re"}}}`, map[string]any{"a": "hello", "re": "("}, DecisionDeny},
		{"semverGt", `{compare: {left: {path: "v"}, op: "semverGt", right: {literal: "1.2.0"}}}`, map[string]any{"v": "1.10.0"}, DecisionAllow},
		{"semverLte", `{compare: {left: {path: "v"}, op: "semverLte", right: {literal: "1.2.0"}}}`, map[string]any{"v": "1.10.0"}, DecisionDeny},
		{"semverEq bad", `{compare: {left: {path: "v"}, op: "semverEq", right: {literal: "1.2.0"}}}`, map[string]any{"v": "x"}, DecisionDeny},
		{"after", `{compare: {left: {path: "t"}, op: "after", right: {literal: "2020-01-01"}}}`, map[string]any{"t": "2021-01-01"}, DecisionAllow},
		{"beforeOrEqual", `{compare: {left: {path: "t"}, op: "beforeOrEqual", right: {literal: "2020-01-01"}}}`, map[string]any{"t": "2021-01-01"}, DecisionDeny},
		{"func operand", `{compare: {left: {func: {name: "len", args: [{path: "xs"}]}}, op: ">=", right: {literal: 2}}}`, map[string]any{"xs": []any{1.0, 2.0}}, DecisionAllow},
		{"func operand error", `{compare: {left: {func: {name: "lower", args: [{path: "n"}]}}, op: "==", right: {literal: "x"}}}`, map[string]any{"n": 1.0}, DecisionDeny},

		{"semver constraint caret", `{match: {path: "v", semver: {constraint: "^1.2.0"}}}`, map[string]any{"v": "1.9.0"}, DecisionAllow},
		{"semver constraint caret major", `{match: {path: "v", semver: {constraint: "^1.2.0"}}}`, map[string]any{"v": "2.0.0"}, DecisionDeny},
		{"semver constraint tilde", `{match: {path: "v", semver: {constraint: "~1.2.0"}}}`, map[string]any{"v": "1.3.0"}, DecisionDeny},
		{"semver constraint range", `{match: {path: "v", semver: {constraint: ">=1.0.0, <2.0.0"}}}`, map[string]any{"v": "1.5.0"}, DecisionAllow},
		{"semver constraint exact", `{match: {path: "v", semver: {constraint: "=1.0.0"}}}`, map[string]any{"v": "1.0.1"}, DecisionDeny},
		{"semver constraint bare", `{match: {path: "v", semver: {constraint: "1.0.0"}}}`, map[string]any{"v": "1.0.0"}, DecisionAllow},
		{"semver constraint lte", `{match: {path: "v", semver: {constraint: "<=1.0.0"}}}`, map[string]any{"v": "1.0.0"}, DecisionAllow},
		{"semver constraint gt", `{match: {path: "v", semver: {constraint: ">1.0.0"}}}`, map[string]any{"v": "1.0.0"}, DecisionDeny},
		{"semver non-string", `{match: {path: "v", semver: {equals: "1.0.0"}}}`, map[string]any{"v": 1.0}, DecisionDeny},
		{"datetime afterOrEqual now", `{match: {path: "t", datetime: {afterOrEqual: "now"}}}`, map[string]any{"t": "2000-01-01"}, DecisionDeny},
		{"datetime withinHours", `{match: {path: "t", datetime: {withinHours: 1}}}`, map[string]any{"t": "2000-01-01"}, DecisionDeny},
		{"datetime notExpired false", `{match: {path: "t", datetime: {notExpired: false}}}`, map[string]any{"t": "2000-01-01"}, DecisionAllow},
		{"datetime non-string", `{match: {path: "t", datetime: {before: "now"}}}`, map[string]any{"t": 5.0}, DecisionDeny},
		{"length equals", `{match: {path: "s", length: {equals: 2}}}`, map[string]any{"s": []any{1.0}}, DecisionDeny},
		{"length on a number", `{match: {path: "s", length: {lessThan: 2}}}`, map[string]any{"s": 1.0}, DecisionDeny},
		{"hasSuffix match", `{match: {path: "s", hasSuffix: "z"}}`, map[string]any{"s": "abc"}, DecisionDeny},
		{"unique false", `{match: {path: "s", unique: false}}`, map[string]any{"s": []any{1.0, 1.0}}, DecisionAllow},
		{"uniqueBy missing field", `{match: {path: "s", uniqueBy: "id"}}`, map[string]any{"s": []any{map[string]any{}}}, DecisionDeny},
		{"containsAny miss", `{match: {path: "s", containsAny: ["x"]}}`, map[string]any{"s": []any{"y"}}, DecisionDeny},
		{"all of nothing", `{all: []}`, map[string]any{}, DecisionAllow},
		{"any of nothing", `{any: []}`, map[string]any{}, DecisionDeny},
		{"forEach any", `{forEach: {path: "xs", mode: "any", condition: {match: {path: "item", equals: 2}}}}`, map[string]any{"xs": []any{1.0, 2.0}}, DecisionAllow},
		{"forEach any none", `{forEach: {path: "xs", mode: "any", condition: {match: {path: "item", equals: 3}}}}`, map[string]any{"xs": []any{1.0, 2.0}}, DecisionDeny},
		{"forEach empty disallowed", `{forEach: {path: "xs", allowEmpty: false, condition: {match: {path: "item", equals: 3}}}}`, map[string]any{"xs": []any{}}, DecisionDeny},
		{"forEach missing", `{forEach: {path: "xs", condition: {match: {path: "item", equals: 3}}}}`, map[string]any{}, DecisionDeny},
		{"func expect mismatch", `{func: {name: "len", args: [{path: "xs"}], expect: 3}}`, map[string]any{"xs": []any{1.0}}, DecisionDeny},
		{"func falsey", `{func: {name: "len", args: [{path: "xs"}]}}`, map[string]any{"xs": []any{}}, DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decide(t, tt.expr, tt.input).Decision; got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}
}

// Malformed operands are load errors, not per-request failures.
func TestCompileErrors(t *testing.T) {
	bad := []string{
		`{match: {path: "a..b", equals: 1}}`,
		`{match: {path: "a", pattern: "("}}`,
		`{match: {path: "a", semver: {equals: "nope"}}}`,
		`{match: {path: "a", semver: {constraint: ">=x"}}}`,
		`{match: {path: "a", semver: {}}}`,
		`{match: {path: "a", datetime: {after: "someday"}}}`,
		`{match: {path: "a", length: {}}}`,
		`{match: {path: "a"}}`,
		`{match: {path: "a", uniqueBy: "b..c"}}`,
		`{compare: {left: {path: "a"}, op: "matches", right: {literal: "("}}}`,
		`{compare: {left: {path: "a"}, op: "matches", right: {literal: 1}}}`,
		`{compare: {left: {path: "a", literal: 1}, op: "==", right: {literal: 1}}}`,
		`{forEach: {path: "xs", as: "_index", condition: {match: {path: "x", equals: 1}}}}`,
		`{forEach: {path: "xs"}}`,
		`{forEach: {path: "xs", condition: {match: {path: "_index.x", equals: 1}}}}`,
		`{func: {name: "len", args: [{nope: 1}]}}`,
	}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			rule := `{id: "r1", description: "d", severity: "high", expr: ` + expr + `}`
			src := makePolicy("p", "default", "d", rule, "deny", "")
			err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", src)
			if err == nil {
				t.Fatal("policy loaded; it must be rejected")
			}
		})
	}
}

// Message placeholders are filled from bindings (length, version, datetime,
// and func bind names).
func TestMessageBindings(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high",
		expr: {all: [{func: {name: "len", args: [{path: "xs"}], bind: "n"}}, {match: {path: "xs", length: {greaterThan: 5}}}]},
		message: "got {{.n}} items (length {{.length}})"}`
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"xs": []any{1.0, 2.0}}})
	if err != nil {
		t.Fatal(err)
	}
	if msg := resp.Results[0].Message; msg != "got 2 items (length 2)" {
		t.Errorf("message = %q", msg)
	}
}

// The kind index merges concrete-kind and wildcard policies in key order.
func TestKindIndexMerge(t *testing.T) {
	eng := newTestEngine(t)
	for _, p := range []struct{ name, target string }{
		{"a-wild", `"*"`}, {"b-pod", `"Pod"`}, {"c-wild", `{kind: "P*"}`}, {"d-deploy", `"Deployment"`}, {"e-pod", `{kind: "pod"}`},
	} {
		src := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "` + p.name + `", namespace: "default"}
spec: {
	target: resources: [` + p.target + `]
	rules: [{id: "r1", description: "d", severity: "high", expr: match: {path: "kind", exists: true}}]
	enforcement: action: "deny"
}`
		if err := eng.LoadPolicy(context.Background(), p.name, "default", src); err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
	}
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"kind": "Pod"},
		Options: EvaluateOptions{IncludePassed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range resp.Results {
		got = append(got, r.PolicyName)
	}
	if strings.Join(got, ",") != "a-wild,b-pod,c-wild,e-pod" {
		t.Errorf("policies evaluated = %v, want a-wild,b-pod,c-wild,e-pod in key order", got)
	}
}
