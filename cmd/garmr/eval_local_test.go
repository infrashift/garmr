package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/api"
	"github.com/infrashift/garmr/internal/client"
	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/server"
)

// testFindingsPolicy reports each major review finding as a structured
// finding.
const testFindingsPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "review-findings"
	namespace: "review"
}
spec: {
	description: "No major findings"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "VZ-001"
		description: "no major findings"
		severity:    "high"
		expr: forEach: {
			path:         "findings"
			as:           "f"
			allowMissing: true
			condition: not: match: {path: "f.severity", equals: "major"}
		}
		message: "{{f.file}}:{{f.start_line}} is a major finding"
		details: {file: "f.file", line: "f.start_line"}
	}]
	enforcement: action: "deny"
}
`

// localEvalFlagSet registers every flag runEval reads, including the
// local-evaluation flags.
func localEvalFlagSet(t *testing.T) *cobraCmd {
	t.Helper()
	return localEvalFlagSetWithNamespace(t, "")
}

// writePolicyDir writes each bare policy fixture into dir as a named
// document of one CUE package, the on-disk form the directory loader reads.
func writePolicyDir(t *testing.T, sources ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i, src := range sources {
		doc := "package policy\n\np" + string(rune('a'+i)) + ": {" + src + "}\n"
		path := filepath.Join(dir, "p"+string(rune('a'+i))+".cue")
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return dir
}

// startDirServer boots a real server whose engine is loaded from dir, the
// way garmr-server loads at startup.
func startDirServer(t *testing.T, dir string) {
	t.Helper()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err = eng.LoadPoliciesFromDir(context.Background(), dir); err != nil {
		t.Fatalf("LoadPoliciesFromDir: %v", err)
	}
	srv, err := server.NewServer(server.Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	viper.Reset()
	viper.Set("server", ts.URL)
	viper.Set("output", "json")
}

type evalRun struct {
	body map[string]any
	exit int
}

// runEvalJSON runs runEval with -o json, returning the decoded output (with
// the wall-clock timing masked) and the exit code (0 when none).
func runEvalJSON(t *testing.T, cmd *cobraCmd) evalRun {
	t.Helper()
	viperSetOutput(t, "json")
	rec := stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
	var body map[string]any
	if err := json.Unmarshal([]byte(stdout), &body); err != nil {
		t.Fatalf("decode output %q: %v", stdout, err)
	}
	if m, ok := body["metrics"].(map[string]any); ok {
		m["evaluation_time_ns"] = 0
	}
	exit := 0
	if rec.Called {
		exit = rec.Code
	}
	return evalRun{body, exit}
}

// TestRunEval_LocalMatchesServer pins the contract of --local: for the same
// policies and input, the output and exit code are exactly what a server
// loaded from the same directory returns.
func TestRunEval_LocalMatchesServer(t *testing.T) {
	dir := writePolicyDir(t, testPassPolicy, testDenyPolicy, testWarnPolicy, testSecurityPolicy, testFindingsPolicy)

	cases := []struct {
		name      string
		data      string
		format    string
		namespace string
		policies  []string
		verbose   string
	}{
		{name: "deny across namespaces", data: `{"status":"active","env":"staging"}`},
		{name: "allow in namespace", data: `{"tls":true}`, namespace: "security"},
		{name: "deny in namespace", data: `{"tls":false}`, namespace: "security"},
		{name: "warn only", data: `{"x":2}`, policies: []string{"default/warn-policy"}},
		{name: "verbose includes passed", data: `{"status":"active","env":"production","x":1}`, verbose: "true"},
		{name: "no match fails closed", data: `{"a":1}`, namespace: "nothing-here"},
		{name: "yaml input", data: "status: active\nenv: production\nx: 1\n", format: "yaml"},
		{name: "structured findings", namespace: "review",
			data: `{"findings":[{"file":"a.go","start_line":3,"severity":"minor"},{"file":"b.go","start_line":12,"severity":"major"}]}`},
		{name: "omitted list", namespace: "review", data: `{"verdict":"approve"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configure := func(cmd *cobraCmd) {
				cmd.Flags().Set("data", tc.data)
				cmd.Flags().Set("request-id", "req-parity")
				if tc.format != "" {
					cmd.Flags().Set("format", tc.format)
				}
				if tc.verbose != "" {
					cmd.Flags().Set("verbose", tc.verbose)
				}
				for _, p := range tc.policies {
					cmd.Flags().Set("policy", p)
				}
			}

			startDirServer(t, dir)
			remoteCmd := localEvalFlagSetWithNamespace(t, tc.namespace)
			configure(remoteCmd)
			remote := runEvalJSON(t, remoteCmd)

			localCmd := localEvalFlagSetWithNamespace(t, tc.namespace)
			configure(localCmd)
			localCmd.Flags().Set("policy-dir", dir)
			local := runEvalJSON(t, localCmd)

			if !reflect.DeepEqual(remote, local) {
				rb, _ := json.MarshalIndent(remote.body, "", "  ")
				lb, _ := json.MarshalIndent(local.body, "", "  ")
				t.Errorf("local differs from server\nserver (exit %d):\n%s\nlocal (exit %d):\n%s",
					remote.exit, rb, local.exit, lb)
			}
		})
	}
}

// localEvalFlagSetWithNamespace builds the full flag set, declaring
// namespace as a string the way the real eval command does.
func localEvalFlagSetWithNamespace(t *testing.T, namespace string) *cobraCmd {
	t.Helper()
	cmd := newTestCmd(t,
		flagSpec{Kind: "string", Name: "input"},
		flagSpec{Kind: "string", Name: "data"},
		flagSpec{Kind: "string", Name: "format", Value: "auto"},
		flagSpec{Kind: "stringSlice", Name: "policy"},
		flagSpec{Kind: "string", Name: "namespace", Value: namespace},
		flagSpec{Kind: "bool", Name: "verbose"},
		flagSpec{Kind: "string", Name: "request-id"},
		flagSpec{Kind: "bool", Name: "quiet"},
		flagSpec{Kind: "bool", Name: "local"},
		flagSpec{Kind: "string", Name: "policy-dir"},
		flagSpec{Kind: "duration", Name: "timeout", Value: api.DefaultEvaluationTimeout},
	)
	return cmd
}

func TestRunEval_LocalDenyExits1WithoutServer(t *testing.T) {
	viper.Reset()
	viper.Set("server", "http://127.0.0.1:1") // never contacted
	viper.Set("output", "table")
	dir := writePolicyDir(t, testDenyPolicy)

	cmd := localEvalFlagSet(t)
	cmd.Flags().Set("local", "true")
	cmd.Flags().Set("policy-dir", dir)
	cmd.Flags().Set("data", `{"env":"staging"}`)

	rec := stubExit(t)
	stdout, _ := captureOutput(t, func() { _ = runEval(cmd, nil) })
	if rec.Code != exitNegative {
		t.Errorf("exit = %d, want %d", rec.Code, exitNegative)
	}
	if !strings.Contains(stdout, "DENY") {
		t.Errorf("missing DENY in output: %q", stdout)
	}
}

func TestRunEval_LocalSingleFile(t *testing.T) {
	viper.Reset()
	viper.Set("output", "table")
	dir := writePolicyDir(t, testPassPolicy)

	cmd := localEvalFlagSet(t)
	cmd.Flags().Set("policy-dir", filepath.Join(dir, "pa.cue"))
	cmd.Flags().Set("data", `{"status":"active"}`)

	rec := stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
	if rec.Called {
		t.Errorf("unexpected exit %d", rec.Code)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("missing ALLOW in output: %q", stdout)
	}
}

func TestRunEval_LocalGeneratesRequestID(t *testing.T) {
	viper.Reset()
	dir := writePolicyDir(t, testPassPolicy)

	cmd := localEvalFlagSet(t)
	cmd.Flags().Set("policy-dir", dir)
	cmd.Flags().Set("data", `{"status":"active"}`)

	got := runEvalJSON(t, cmd)
	if id, _ := got.body["request_id"].(string); len(id) != 36 {
		t.Errorf("request_id = %q, want a generated UUID", id)
	}
}

func TestRunEval_LocalErrors(t *testing.T) {
	viper.Reset()
	good := writePolicyDir(t, testPassPolicy)
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "bad.cue"), []byte("package policy\n\nx: {kind: \"Policy\", spec: 1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		flags   map[string]string
		wantErr string
	}{
		{"local without dir", map[string]string{"local": "true", "data": `{}`}, "--local requires --policy-dir"},
		{"missing dir", map[string]string{"policy-dir": filepath.Join(good, "nope"), "data": `{}`}, "policy dir"},
		{"invalid policy fails closed", map[string]string{"policy-dir": bad, "data": `{}`}, "loading policies"},
		{"empty dir fails closed", map[string]string{"policy-dir": t.TempDir(), "data": `{}`}, "loading policies"},
		{"bad input", map[string]string{"policy-dir": good, "data": `not json`}, "reading input"},
		{"timeout", map[string]string{"policy-dir": good, "data": `{"status":"active"}`, "timeout": "1ns"}, "evaluation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := localEvalFlagSet(t)
			for k, v := range tc.flags {
				if err := cmd.Flags().Set(k, v); err != nil {
					t.Fatalf("set %s: %v", k, err)
				}
			}
			stubExit(t)
			var err error
			captureOutput(t, func() { err = runEval(cmd, nil) })
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestJSONRoundTrip_NormalizesNumbers(t *testing.T) {
	out, err := jsonRoundTrip(map[string]interface{}{"n": 3, "l": []interface{}{int64(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out["n"].(float64); !ok {
		t.Errorf("n = %T, want float64", out["n"])
	}
	if _, err := jsonRoundTrip(map[string]interface{}{"c": make(chan int)}); err == nil {
		t.Error("expected an encoding error for an unencodable value")
	}
}

func TestRunEval_FindingsRendering(t *testing.T) {
	dir := writePolicyDir(t, testFindingsPolicy)
	input := `{"findings":[{"file":"b.go","start_line":12,"severity":"major"},{"file":"c.go","severity":"major"}]}`

	for _, format := range []string{"table", "yaml", "json"} {
		t.Run(format, func(t *testing.T) {
			viper.Reset()
			viperSetOutput(t, format)
			cmd := localEvalFlagSet(t)
			cmd.Flags().Set("policy-dir", dir)
			cmd.Flags().Set("data", input)

			stubExit(t)
			stdout, _ := captureOutput(t, func() { _ = runEval(cmd, nil) })

			var want []string
			switch format {
			case "table":
				want = []string{"• findings[0] file=b.go line=12", "• findings[1] file=c.go"}
			case "yaml":
				want = []string{"findings:", "- path: findings[0]", "file: b.go", "line: 12", "- path: findings[1]"}
			case "json":
				want = []string{`"path": "findings[0]"`, `"file": "b.go"`, `"line": 12`}
			}
			for _, w := range want {
				if !strings.Contains(stdout, w) {
					t.Errorf("output missing %q:\n%s", w, stdout)
				}
			}
		})
	}
}

func TestOutputFindingsTruncated(t *testing.T) {
	result := &client.EvaluateResult{Decision: "deny", Results: []client.RuleResult{{
		RuleID: "r1", Severity: "high", Findings: []client.Finding{{Path: "xs[0]"}}, FindingsTruncated: true,
	}}}
	table, _ := captureOutput(t, func() { _ = outputTable(result, false, false) })
	if !strings.Contains(table, "more failing elements not listed") {
		t.Errorf("table output does not mark truncation:\n%s", table)
	}
	yaml, _ := captureOutput(t, func() { _ = outputYAML(result) })
	if !strings.Contains(yaml, "findings_truncated: true") {
		t.Errorf("yaml output does not mark truncation:\n%s", yaml)
	}
}

// --local validates the input against spec.inputSchema; the server path
// does not, so the same input evaluates there.
func TestRunEval_LocalChecksInputSchema(t *testing.T) {
	policy := strings.Replace(testDenyPolicy, `description: "Policy that denies"`,
		`description: "Policy that denies"
	inputSchema: close({env: "production" | "staging"})`, 1)
	dir := writePolicyDir(t, policy)

	cmd := localEvalFlagSet(t)
	cmd.Flags().Set("policy-dir", dir)
	cmd.Flags().Set("data", `{"env":"production","region":"eu-west-1"}`)
	stubExit(t)
	var err error
	captureOutput(t, func() { err = runEval(cmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "region: field not allowed") {
		t.Errorf("err = %v, want the schema violation reported", err)
	}

	startDirServer(t, dir)
	remote := localEvalFlagSet(t)
	remote.Flags().Set("data", `{"env":"production","region":"eu-west-1"}`)
	if got := runEvalJSON(t, remote); got.body["decision"] != "allow" {
		t.Errorf("server decision = %v, want allow (the server does not check inputSchema)", got.body["decision"])
	}
}

func TestRunEval_WaivedRendering(t *testing.T) {
	policy := strings.Replace(testFindingsPolicy, `enforcement: action: "deny"`, `enforcement: {
		action: "deny"
		exceptions: [{name: "accepted", reason: "tracked", rules: ["VZ-001"],
			findings: {as: "f", where: match: {path: "f.fingerprint", equals: "fp-b"}}}]
	}`, 1)
	dir := writePolicyDir(t, policy)
	input := `{"findings":[{"file":"b.go","start_line":12,"severity":"major","fingerprint":"fp-b"}]}`

	for format, want := range map[string][]string{
		"table": {"ALLOW", "PASS", "○ waived by accepted: findings[0] file=b.go line=12"},
		"yaml":  {"waived:", "- path: findings[0]", "exception: accepted"},
		"json":  {`"waived"`, `"exception": "accepted"`},
	} {
		t.Run(format, func(t *testing.T) {
			viper.Reset()
			viperSetOutput(t, format)
			cmd := localEvalFlagSet(t)
			cmd.Flags().Set("policy-dir", dir)
			cmd.Flags().Set("data", input)
			rec := stubExit(t)
			stdout, _ := captureOutput(t, func() { _ = runEval(cmd, nil) })
			if rec.Called {
				t.Errorf("exit %d, want 0: the only major finding is waived", rec.Code)
			}
			for _, w := range want {
				if !strings.Contains(stdout, w) {
					t.Errorf("output missing %q:\n%s", w, stdout)
				}
			}
		})
	}
}
