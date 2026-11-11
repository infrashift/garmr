package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reviewSchema is a producer's report contract, as a policy would import it.
const reviewSchema = `
#Finding: {
	file:        string
	start_line?: int
	severity:    "minor" | "major"
	fingerprint?: string
	refs?: [...{url: string}]
}
#ReviewReport: {
	verdict:    "approve" | "reject"
	risk_score: int
	findings?: [...#Finding]
	labels?: [string]: string
	extra?: {...}
	anything?: _
	choice?: {a: int} | {b: int}
}
`

// schemaPolicy is a policy with spec.inputSchema: #ReviewReport and the
// given rules.
func schemaPolicy(rules string) string {
	return reviewSchema + fmt.Sprintf(`
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "review", namespace: "default"}
spec: {
	description: "d"
	inputSchema: #ReviewReport
	target: resources: [{kind: "*"}]
	rules: [%s]
	enforcement: action: "deny"
}`, rules)
}

func loadSchemaPolicy(t *testing.T, rules string) (*Engine, error) {
	t.Helper()
	eng := newTestEngine(t)
	return eng, eng.LoadPolicy(context.Background(), "review", "default", schemaPolicy(rules))
}

func TestInputSchema_PathsCheckedAtLoad(t *testing.T) {
	rule := func(body string) string {
		return `{id: "r1", description: "d", severity: "high", ` + body + `}`
	}
	ok := map[string]string{
		"top-level field":        rule(`expr: match: {path: "risk_score", lessThan: 5}`),
		"optional list elements": rule(`expr: forEach: {path: "findings", as: "f", allowMissing: true, condition: match: {path: "f.severity", equals: "minor"}}`),
		"projection":             rule(`expr: match: {path: "findings[*].file", unique: true}`),
		"index":                  rule(`expr: match: {path: "findings[0].start_line", exists: true}`),
		"nested forEach":         rule(`expr: forEach: {path: "findings", as: "f", condition: forEach: {path: "f.refs", as: "r", condition: match: {path: "r.url", hasPrefix: "https://"}}}`),
		"pattern field":          rule(`expr: match: {path: "labels.team", exists: true}`),
		"open struct":            rule(`expr: match: {path: "extra.whatever.deep", exists: true}`),
		"top value":              rule(`expr: match: {path: "anything.x[3].y", exists: true}`),
		"disjunction field":      rule(`expr: match: {path: "choice.a", equals: 1}`),
		"compare and func":       rule(`expr: compare: {left: {func: {name: "len", args: [{path: "findings"}]}}, op: "<=", right: {path: "risk_score"}}`),
		"index placeholder":      rule(`expr: forEach: {path: "findings", as: "f", condition: match: {path: "f.file", exists: true}}, message: "#{{_index}}"`),
		"details and message": rule(`expr: forEach: {path: "findings", as: "f", condition: match: {path: "f.file", exists: true}},
			message: "{{f.file}} in {{verdict}}", details: {line: "f.start_line", score: "risk_score"}`),
	}
	for name, r := range ok {
		t.Run("ok/"+name, func(t *testing.T) {
			if _, err := loadSchemaPolicy(t, r); err != nil {
				t.Errorf("load failed: %v", err)
			}
		})
	}

	bad := map[string]struct{ rule, want string }{
		"typo":                {rule(`expr: match: {path: "risk_scor", lessThan: 5}`), `does not allow field "risk_scor"`},
		"element typo":        {rule(`expr: forEach: {path: "findings", as: "f", condition: match: {path: "f.severity_level", equals: "minor"}}`), `"severity_level" in 'findings[*]'`},
		"list typo":           {rule(`expr: forEach: {path: "finding", as: "f", condition: match: {path: "f.file", exists: true}}`), `"finding"`},
		"field of a scalar":   {rule(`expr: match: {path: "verdict.kind", equals: "x"}`), "has no field"},
		"index of a struct":   {rule(`expr: match: {path: "labels[0]", equals: "x"}`), "not a list"},
		"when":                {rule(`when: match: {path: "verdikt", equals: "approve"}, expr: match: {path: "risk_score", lessThan: 5}`), `"verdikt"`},
		"where":               {rule(`expr: forEach: {path: "findings", as: "f", where: match: {path: "f.sev", equals: "major"}, condition: match: {path: "f.file", exists: true}}`), `"sev"`},
		"compare":             {rule(`expr: compare: {left: {path: "risk_score"}, op: "<", right: {path: "risk_max"}}`), `"risk_max"`},
		"func arg":            {rule(`expr: func: {name: "len", args: [{path: "findngs"}], expect: 0}`), `"findngs"`},
		"message input":       {rule(`expr: match: {path: "risk_score", lessThan: 5}, message: "score {{risk}}"`), "message:"},
		"message alias":       {rule(`expr: forEach: {path: "findings", as: "f", condition: match: {path: "f.file", exists: true}}, message: "{{f.path}}"`), `"path"`},
		"details":             {rule(`expr: forEach: {path: "findings", as: "f", condition: match: {path: "f.file", exists: true}}, details: {line: "f.line"}`), "details.line"},
		"disjunction":         {rule(`expr: match: {path: "choice.z", equals: 1}`), `"z"`},
		"nested element typo": {rule(`expr: forEach: {path: "findings", as: "f", condition: forEach: {path: "f.refs", as: "r", condition: match: {path: "r.uri", exists: true}}}`), `"uri" in 'findings[*].refs[*]'`},
	}
	for name, tc := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			_, err := loadSchemaPolicy(t, tc.rule)
			if err == nil {
				t.Fatal("load succeeded, want a path error")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "rule r1") {
				t.Errorf("err = %v\nwant it to name rule r1 and contain %q", err, tc.want)
			}
		})
	}
}

// The server path never consults the schema: evaluation stays CUE-free and
// a non-conforming input is evaluated as before.
func TestInputSchema_NotCheckedByDefault(t *testing.T) {
	eng, err := loadSchemaPolicy(t, `{id: "r1", description: "d", severity: "high", expr: match: {path: "risk_score", lessThan: 5}}`)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"risk_score": 3.0, "unknown": true}})
	if err != nil || resp.Decision != DecisionAllow {
		t.Errorf("decision %v, err %v; want allow with no schema check", resp, err)
	}
}

func TestInputSchema_CheckedWhenRequested(t *testing.T) {
	eng, err := loadSchemaPolicy(t, `{id: "r1", description: "d", severity: "high", expr: match: {path: "risk_score", lessThan: 5}}`)
	if err != nil {
		t.Fatal(err)
	}
	eval := func(input map[string]any) (*EvaluateResponse, error) {
		return eng.Evaluate(context.Background(), &EvaluateRequest{Input: input, Options: EvaluateOptions{CheckInputSchema: true}})
	}

	// JSON numbers arrive as float64; a whole one must still satisfy int.
	resp, err := eval(map[string]any{"verdict": "approve", "risk_score": 3.0, "findings": []any{map[string]any{"file": "a.go", "severity": "minor", "start_line": 4.0}}})
	if err != nil || resp.Decision != DecisionAllow {
		t.Fatalf("conforming input: decision %v, err %v", resp, err)
	}

	cases := map[string]struct {
		input map[string]any
		want  []string
	}{
		"missing required": {map[string]any{"verdict": "approve"}, []string{"risk_score: incomplete value int"}},
		"unknown field":    {map[string]any{"verdict": "approve", "risk_score": 1.0, "risk_scor": 1.0}, []string{"risk_scor: field not allowed"}},
		"wrong enum":       {map[string]any{"verdict": "maybe", "risk_score": 1.0}, []string{"verdict"}},
		"float for int":    {map[string]any{"verdict": "approve", "risk_score": 1.5}, []string{"risk_score"}},
		"element field":    {map[string]any{"verdict": "approve", "risk_score": 1.0, "findings": []any{map[string]any{"file": "a.go", "severity": "major", "line": 3.0}}}, []string{"findings.0.line: field not allowed"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := eval(tc.input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
			for _, w := range append(tc.want, "default/review") {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %v\nwant it to contain %q", err, w)
				}
			}
			if strings.Contains(err.Error(), "_#") {
				t.Errorf("err = %v, leaks the rendered schema's internal names", err)
			}
		})
	}
}

// A policy that an exception skips for this input does not impose its
// input contract either.
func TestInputSchema_SkippedForExceptedPolicy(t *testing.T) {
	src := strings.Replace(schemaPolicy(`{id: "r1", description: "d", severity: "high", expr: match: {path: "risk_score", lessThan: 5}}`),
		`enforcement: action: "deny"`,
		`enforcement: {action: "deny", exceptions: [{name: "x", reason: "r", match: kind: "Legacy"}]}`, 1)
	eng := newTestEngine(t)
	if err := eng.LoadPolicy(context.Background(), "review", "default", src); err != nil {
		t.Fatal(err)
	}
	_, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"kind": "Legacy", "not": "a report"},
		Options: EvaluateOptions{CheckInputSchema: true},
	})
	if err != nil {
		t.Errorf("err = %v, want the excepted policy's schema ignored", err)
	}
}

func TestInputSchema_ErrorListCapped(t *testing.T) {
	input := map[string]any{"verdict": "approve", "risk_score": 1.0}
	for i := 0; i < maxInputSchemaErrors+3; i++ {
		input[fmt.Sprintf("x%02d", i)] = 1.0
	}
	eng, err := loadSchemaPolicy(t, `{id: "r1", description: "d", severity: "high", expr: match: {path: "risk_score", lessThan: 5}}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = eng.Evaluate(context.Background(), &EvaluateRequest{Input: input, Options: EvaluateOptions{CheckInputSchema: true}})
	if err == nil || !strings.Contains(err.Error(), "and 3 more") {
		t.Errorf("err = %v, want the list capped with 'and 3 more'", err)
	}
}

// The digest covers the schema: changing the contract changes the policy.
func TestInputSchema_InPolicyHash(t *testing.T) {
	rules := `{id: "r1", description: "d", severity: "high", expr: match: {path: "risk_score", lessThan: 5}}`
	hash := func(src string) string {
		eng := newTestEngine(t)
		if err := eng.LoadPolicy(context.Background(), "review", "default", src); err != nil {
			t.Fatal(err)
		}
		return eng.set.Load().policies[policyKey("default", "review")].Hash
	}
	a, b := hash(schemaPolicy(rules)), hash(schemaPolicy(rules))
	c := hash(strings.Replace(schemaPolicy(rules), "risk_score: int", "risk_score: int & >=0", 1))
	if a != b || a == c {
		t.Errorf("hashes: same source %v, changed schema %v; want stable and sensitive to the schema", a == b, a != c)
	}
}

// The schema is usually imported from the producer's package. Imports are
// resolved by the loader against the policy repository's cue.mod, so a
// vendored or in-repo schema package works offline.
func TestInputSchema_ImportedPackage(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cue.mod/module.cue", "module: \"example.com/policies\"\nlanguage: version: \"v0.9.0\"\n")
	write("schema/report/report.cue", "package report\n"+reviewSchema)
	write("review/policy.cue", `package review

import "example.com/policies/schema/report"

review: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {name: "review", namespace: "review"}
	spec: {
		inputSchema: report.#ReviewReport
		target: resources: [{kind: "*"}]
		rules: [{id: "r1", description: "d", severity: "high", expr: match: {path: "risk_score", lessThan: 5}}]
		enforcement: action: "deny"
	}
}
`)
	eng := newTestEngine(t)
	if err := eng.LoadPoliciesFromDir(context.Background(), dir); err != nil {
		t.Fatalf("LoadPoliciesFromDir: %v", err)
	}
	_, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"verdict": "approve", "risk_score": 1.0, "risk_scor": 2.0}, Namespace: "review",
		Options: EvaluateOptions{CheckInputSchema: true},
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "risk_scor") {
		t.Errorf("err = %v, want the imported schema enforced", err)
	}

	// And a typo against the imported schema fails the directory load.
	write("review/policy.cue", strings.Replace(mustRead(t, filepath.Join(dir, "review/policy.cue")), `path: "risk_score"`, `path: "risk_scor"`, 1))
	if err := newTestEngine(t).LoadPoliciesFromDir(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "risk_scor") {
		t.Errorf("err = %v, want the load to reject the misspelled path", err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
