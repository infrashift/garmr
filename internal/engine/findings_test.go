package engine

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// decideDetails evaluates one rule with the given `details` CUE struct.
func decideDetails(t *testing.T, expr, details string, input map[string]any) RuleResult {
	t.Helper()
	rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "high", expr: %s, details: %s}`, expr, details)
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input, Options: EvaluateOptions{IncludePassed: true}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(resp.Results))
	}
	return resp.Results[0]
}

func reviewInput(findings ...map[string]any) map[string]any {
	list := make([]any, len(findings))
	for i, f := range findings {
		list[i] = f
	}
	return map[string]any{"pr": 42.0, "findings": list}
}

const majorFindingsExpr = `{forEach: {path: "findings", as: "f", condition: {not: {match: {path: "f.severity", equals: "major"}}}}}`

func TestFindings_ReportFailingElements(t *testing.T) {
	r := decideDetails(t, majorFindingsExpr,
		`{file: "f.file", line: "f.start_line", pr: "pr", pos: "_index", missing: "f.nope"}`,
		reviewInput(
			map[string]any{"file": "a.go", "start_line": 3.0, "severity": "minor"},
			map[string]any{"file": "b.go", "start_line": 12.0, "severity": "major"},
			map[string]any{"file": "c.go", "severity": "major"},
		))

	if r.Passed {
		t.Fatal("rule passed, want a failure")
	}
	want := []Finding{
		{Path: "findings[1]", Index: 1, Details: map[string]any{"file": "b.go", "line": 12.0, "pr": 42.0, "pos": 1}},
		{Path: "findings[2]", Index: 2, Details: map[string]any{"file": "c.go", "pr": 42.0, "pos": 2}},
	}
	if !reflect.DeepEqual(r.Findings, want) {
		t.Errorf("findings = %#v\nwant       %#v", r.Findings, want)
	}
	if r.FindingsTruncated {
		t.Error("findings truncated with only two failures")
	}
}

func TestFindings_NestedForEachPath(t *testing.T) {
	expr := `{forEach: {path: "spec.containers", as: "c", condition: {forEach: {path: "c.ports", as: "p",
		condition: {match: {path: "p.containerPort", lessThan: 1024}}}}}}`
	input := pod(
		map[string]any{"name": "web", "ports": []any{map[string]any{"containerPort": 80.0}}},
		map[string]any{"name": "debug", "ports": []any{map[string]any{"containerPort": 80.0}, map[string]any{"containerPort": 9229.0}}},
	)
	r := decideDetails(t, expr, `{container: "c.name", port: "p.containerPort"}`, input)
	want := []Finding{{Path: "spec.containers[1].ports[1]", Index: 1, Details: map[string]any{"container": "debug", "port": 9229.0}}}
	if !reflect.DeepEqual(r.Findings, want) {
		t.Errorf("findings = %#v\nwant       %#v", r.Findings, want)
	}
}

// Findings are only reported by rules that ask for them, only for failing
// elements of a failing rule, and never for checks whose elements did not
// fail (any mode, count, not, a missing list).
func TestFindings_OnlyForFailingElements(t *testing.T) {
	major := map[string]any{"file": "b.go", "severity": "major"}
	cases := []struct {
		name, expr string
		input      map[string]any
	}{
		{"passing rule", majorFindingsExpr, reviewInput(map[string]any{"file": "a.go", "severity": "minor"})},
		{"missing list", majorFindingsExpr, map[string]any{}},
		{"any mode", `{forEach: {path: "findings", as: "f", mode: "any", condition: {match: {path: "f.severity", equals: "minor"}}}}`, reviewInput(major)},
		{"count", `{forEach: {path: "findings", as: "f", count: {equals: 0}, condition: {match: {path: "f.severity", equals: "major"}}}}`, reviewInput(major)},
		{"under not", `{not: {forEach: {path: "findings", as: "f", condition: {match: {path: "f.severity", equals: "major"}}}}}`, reviewInput(major)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := decideDetails(t, tc.expr, `{file: "f.file"}`, tc.input)
			if len(r.Findings) != 0 {
				t.Errorf("findings = %#v, want none", r.Findings)
			}
		})
	}

	// No details, no findings: the hot path records nothing.
	resp := decide(t, majorFindingsExpr, reviewInput(major))
	if len(resp.Results) != 1 || resp.Results[0].Findings != nil {
		t.Errorf("rule without details reported findings: %#v", resp.Results)
	}
}

func TestFindings_Capped(t *testing.T) {
	var many []map[string]any
	for i := 0; i < MaxFindings+5; i++ {
		many = append(many, map[string]any{"file": fmt.Sprintf("f%d.go", i), "severity": "major"})
	}
	r := decideDetails(t, majorFindingsExpr, `{file: "f.file"}`, reviewInput(many...))
	if len(r.Findings) != MaxFindings || !r.FindingsTruncated {
		t.Errorf("findings = %d (truncated %v), want %d truncated", len(r.Findings), r.FindingsTruncated, MaxFindings)
	}
}

// A message and details can be used together; each renders per element.
func TestFindings_WithMessage(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high", expr: ` + majorFindingsExpr + `,
		message: "{{f.file}} has a major finding", details: {file: "f.file"}}`
	eng := loadTestPolicy(t, "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: reviewInput(
		map[string]any{"file": "a.go", "severity": "major"}, map[string]any{"file": "b.go", "severity": "major"})})
	if err != nil {
		t.Fatal(err)
	}
	r := resp.Results[0]
	if r.Message != "a.go has a major finding; b.go has a major finding" || len(r.Findings) != 2 {
		t.Errorf("message %q, %d findings", r.Message, len(r.Findings))
	}
}

func TestFindings_LoadErrors(t *testing.T) {
	cases := map[string]string{
		"no forEach":   `{id: "r1", description: "d", severity: "high", expr: {match: {path: "a", equals: 1}}, details: {a: "a"}}`,
		"bad path":     `{id: "r1", description: "d", severity: "high", expr: ` + majorFindingsExpr + `, details: {a: "f..file"}}`,
		"not a string": `{id: "r1", description: "d", severity: "high", expr: ` + majorFindingsExpr + `, details: {a: 1}}`,
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", makePolicy("p", "default", "d", rule, "deny", ""))
			if err == nil {
				t.Fatal("expected a load error")
			}
			if name == "no forEach" && !strings.Contains(err.Error(), "no forEach") {
				t.Errorf("err = %v, want it to explain that details need a forEach", err)
			}
		})
	}
}
