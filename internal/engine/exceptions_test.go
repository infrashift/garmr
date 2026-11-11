package engine

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Two rules over a review report: REV-001 gates the risk score, REV-002
// fails on any major finding and reports file and fingerprint.
const exceptionRules = `
	{id: "REV-001", description: "risk", severity: "high", expr: match: {path: "risk_score", lessThan: 5}},
	{id: "REV-002", description: "no major findings", severity: "high",
	 expr: forEach: {path: "findings", as: "f", condition: not: match: {path: "f.severity", equals: "major"}},
	 details: {file: "f.file"}},
`

func excPolicy(exceptions string) string {
	return makePolicyFull("review", "default", "d", exceptionRules, "deny", "exceptions: ["+exceptions+"]", "")
}

func evalExc(t *testing.T, exceptions string, input map[string]any) *EvaluateResponse {
	t.Helper()
	eng := loadTestPolicy(t, "review", "default", excPolicy(exceptions))
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return resp
}

func report(risk float64, findings ...map[string]any) map[string]any {
	list := make([]any, len(findings))
	for i, f := range findings {
		list[i] = f
	}
	return map[string]any{"kind": "ReviewReport", "risk_score": risk, "findings": list}
}

func major(file, fp string) map[string]any {
	return map[string]any{"file": file, "severity": "major", "fingerprint": fp}
}

func failedRules(resp *EvaluateResponse) []string {
	var ids []string
	for _, r := range resp.Results {
		if !r.Passed {
			ids = append(ids, r.RuleID)
		}
	}
	return ids
}

func resultFor(t *testing.T, resp *EvaluateResponse, id string) RuleResult {
	t.Helper()
	for _, r := range resp.Results {
		if r.RuleID == id {
			return r
		}
	}
	t.Fatalf("no result for %s in %+v", id, resp.Results)
	return RuleResult{}
}

func TestExceptions_RuleScoped(t *testing.T) {
	input := report(9, major("a.go", "fp-a"))

	// Without an exception both rules fail.
	if got := failedRules(evalExc(t, "", input)); !reflect.DeepEqual(got, []string{"REV-001", "REV-002"}) {
		t.Fatalf("failed = %v, want both rules", got)
	}

	// A rule-scoped exception skips just that rule, with no match needed.
	resp := evalExc(t, `{name: "accept-risk", reason: "r", rules: ["REV-001"]}`, input)
	if got := failedRules(resp); !reflect.DeepEqual(got, []string{"REV-002"}) {
		t.Errorf("failed = %v, want only REV-002", got)
	}
	if resp.Summary.TotalRules != 1 || resp.EvaluationMode.TotalRulesInScope != 1 {
		t.Errorf("rules in scope = %d/%d, want the skipped rule out of scope", resp.Summary.TotalRules, resp.EvaluationMode.TotalRulesInScope)
	}

	// With a match, only selected inputs are exempt.
	other := report(9)
	other["kind"] = "Other"
	resp = evalExc(t, `{name: "accept-risk", reason: "r", rules: ["REV-001"], match: kind: "ReviewReport"}`, other)
	if got := failedRules(resp); !reflect.DeepEqual(got, []string{"REV-001"}) {
		t.Errorf("failed = %v, want REV-001 enforced for a kind the match does not select", got)
	}
}

func TestExceptions_FindingWaiver(t *testing.T) {
	waiver := `{name: "accepted-major", reason: "tracked in JIRA-1", rules: ["REV-002"],
		findings: {as: "f", where: match: {path: "f.fingerprint", in: ["fp-a"]}}}`

	t.Run("all failures waived", func(t *testing.T) {
		resp := evalExc(t, waiver, report(1, major("a.go", "fp-a")))
		if resp.Decision != DecisionAllow {
			t.Errorf("decision = %s, want allow", resp.Decision)
		}
		// Reported anyway, as a passing rule carrying the waiver.
		r := resultFor(t, resp, "REV-002")
		want := []Finding{{Path: "findings[0]", Index: 0, Details: map[string]any{"file": "a.go"}, Exception: "accepted-major"}}
		if !r.Passed || !reflect.DeepEqual(r.Waived, want) {
			t.Errorf("result = %+v, want passed with waived %+v", r, want)
		}
	})

	t.Run("other findings still fail", func(t *testing.T) {
		resp := evalExc(t, waiver, report(1, major("a.go", "fp-a"), major("b.go", "fp-b")))
		r := resultFor(t, resp, "REV-002")
		if r.Passed || len(r.Findings) != 1 || r.Findings[0].Details["file"] != "b.go" || len(r.Waived) != 1 {
			t.Errorf("result = %+v, want b.go failing and a.go waived", r)
		}
	})

	t.Run("expired", func(t *testing.T) {
		expired := strings.Replace(waiver, `reason:`, fmt.Sprintf(`expiry: %q, reason:`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)), 1)
		resp := evalExc(t, expired, report(1, major("a.go", "fp-a")))
		if resp.Decision != DecisionDeny || len(resultFor(t, resp, "REV-002").Waived) != 0 {
			t.Errorf("decision = %s, want an expired waiver to waive nothing", resp.Decision)
		}
	})

	t.Run("match not selected", func(t *testing.T) {
		scoped := strings.Replace(waiver, `rules:`, `match: kind: "Other", rules:`, 1)
		if resp := evalExc(t, scoped, report(1, major("a.go", "fp-a"))); resp.Decision != DecisionDeny {
			t.Errorf("decision = %s, want deny: the exception's match does not select this input", resp.Decision)
		}
	})

	t.Run("selector error waives nothing", func(t *testing.T) {
		// A string compared as a semver is an evaluation error.
		broken := strings.Replace(waiver, `match: {path: "f.fingerprint", in: ["fp-a"]}`, `match: {path: "f.fingerprint", semver: {greaterThan: "1.0.0"}}`, 1)
		if resp := evalExc(t, broken, report(1, major("a.go", "fp-a"))); resp.Decision != DecisionDeny {
			t.Errorf("decision = %s, want deny: a waiver that cannot be evaluated must not waive", resp.Decision)
		}
	})

	t.Run("waived elements are not counted", func(t *testing.T) {
		rules := `{id: "REV-003", description: "at most one major", severity: "high",
			expr: forEach: {path: "findings", as: "f", count: {lessThanOrEqual: 1}, condition: match: {path: "f.severity", equals: "major"}}}`
		src := makePolicyFull("review", "default", "d", rules, "deny",
			`exceptions: [{name: "w", reason: "r", rules: ["REV-003"], findings: {as: "f", where: match: {path: "f.fingerprint", equals: "fp-a"}}}]`, "")
		eng := loadTestPolicy(t, "review", "default", src)
		resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: report(1, major("a.go", "fp-a"), major("b.go", "fp-b"))})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision != DecisionAllow {
			t.Errorf("decision = %s, want allow: one major remains once fp-a is waived", resp.Decision)
		}
	})
}

func TestExceptions_PolicyWideUnchanged(t *testing.T) {
	resp := evalExc(t, `{name: "legacy", reason: "r", match: kind: "ReviewReport"}`, report(9, major("a.go", "fp-a")))
	if resp.Decision != DecisionAllow || len(resp.Results) != 0 {
		t.Errorf("decision = %s with %d results, want the whole policy skipped", resp.Decision, len(resp.Results))
	}
}

func TestExceptions_LoadErrors(t *testing.T) {
	cases := map[string]struct{ exc, want string }{
		"policy-wide without match": {`{name: "x", reason: "r"}`, "match must narrow"},
		"policy-wide match-all":     {`{name: "x", reason: "r", match: kind: "*"}`, "match must narrow"},
		"unknown rule":              {`{name: "x", reason: "r", rules: ["REV-009"]}`, `rule "REV-009" does not exist`},
		"findings without rules":    {`{name: "x", reason: "r", match: kind: "A", findings: {as: "f", where: match: {path: "f.x", exists: true}}}`, "findings requires rules"},
		"alias not in rule":         {`{name: "x", reason: "r", rules: ["REV-002"], findings: {as: "g", where: match: {path: "g.x", exists: true}}}`, `alias "g"`},
		"rule without forEach":      {`{name: "x", reason: "r", rules: ["REV-001"], findings: {as: "f", where: match: {path: "f.x", exists: true}}}`, `alias "f"`},
		"bad where":                 {`{name: "x", reason: "r", rules: ["REV-002"], findings: {as: "f", where: match: {path: "f..x", exists: true}}}`, "findings.where"},
		"empty rules":               {`{name: "x", reason: "r", rules: []}`, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := newTestEngine(t).LoadPolicy(context.Background(), "review", "default", excPolicy(tc.exc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// A waiver's selector is checked against the input schema like any rule
// path, so a misspelled fingerprint field cannot silently waive nothing.
func TestExceptions_WaiverPathsCheckedAgainstSchema(t *testing.T) {
	src := reviewSchema + `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "review", namespace: "default"}
spec: {
	inputSchema: #ReviewReport
	target: resources: [{kind: "*"}]
	rules: [{id: "REV-002", description: "d", severity: "high",
		expr: forEach: {path: "findings", as: "f", condition: not: match: {path: "f.severity", equals: "major"}}}]
	enforcement: {action: "deny", exceptions: [{name: "w", reason: "r", rules: ["REV-002"],
		findings: {as: "f", where: match: {path: "f.fingerprnt", in: ["x"]}}}]}
}`
	err := newTestEngine(t).LoadPolicy(context.Background(), "review", "default", src)
	if err == nil || !strings.Contains(err.Error(), "fingerprnt") {
		t.Errorf("err = %v, want the misspelled waiver path rejected", err)
	}
}
