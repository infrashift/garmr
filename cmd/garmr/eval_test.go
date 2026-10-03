// cmd/garmr/eval_test.go
package main

import (
	"strings"
	"testing"

	"github.com/infrashift/garmr/internal/client"
)

// evalFlagSet returns a fresh cobra.Command pre-configured with every flag
// runEval reads. Callers tweak values via cmd.Flags().Set before invoking
// runEval.
func evalFlagSet(t *testing.T) *cobraCmd {
	t.Helper()
	return newTestCmd(t,
		flagSpec{Kind: "string", Name: "input"},
		flagSpec{Kind: "string", Name: "data"},
		flagSpec{Kind: "string", Name: "format", Value: "auto"},
		flagSpec{Kind: "stringSlice", Name: "policy"},
		flagSpec{Kind: "stringSlice", Name: "namespace"},
		flagSpec{Kind: "bool", Name: "verbose"},
		flagSpec{Kind: "string", Name: "request-id"},
		flagSpec{Kind: "bool", Name: "quiet"},
	)
}

func TestRunEval_AllowDecision(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.json", `{"status":"active"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	rec := stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})

	if rec.Called {
		t.Errorf("did not expect exit; got %d", rec.Code)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("missing ALLOW in output: %q", stdout)
	}
}

func TestRunEval_DenyDecisionExits1(t *testing.T) {
	newTestServer(t, policyFixture{"deny-policy", "default", testDenyPolicy})
	input := writeTempFile(t, "in.json", `{"env":"staging"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	rec := stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})

	if rec.Code != 1 {
		t.Errorf("expected exit 1, got %d", rec.Code)
	}
	if !strings.Contains(stdout, "DENY") {
		t.Errorf("missing DENY in output: %q", stdout)
	}
}

// Warn decisions are advisory by policy design — the CLI never exits non-zero
// on warn. Teams that want warnings to gate CI should change the policy's
// enforcement.action to "deny" instead of overriding from the client.
func TestRunEval_WarnExitsZero(t *testing.T) {
	newTestServer(t, policyFixture{"warn-policy", "default", testWarnPolicy})
	input := writeTempFile(t, "in.json", `{"x":999}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	rec := stubExit(t)
	_, _ = captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})

	if rec.Called {
		t.Errorf("expected no exit for warn decision, got %d", rec.Code)
	}
}

func TestRunEval_JSONOutput(t *testing.T) {
	env := newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	_ = env
	input := writeTempFile(t, "in.json", `{"status":"active"}`)
	viperSetOutput(t, "json")

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})

	if !strings.Contains(stdout, `"decision"`) {
		t.Errorf("expected JSON with decision field; got %q", stdout)
	}
}

func TestRunEval_YAMLOutput(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.json", `{"status":"active"}`)
	viperSetOutput(t, "yaml")

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})

	if !strings.Contains(stdout, "decision:") {
		t.Errorf("expected YAML output; got %q", stdout)
	}
}

func TestRunEval_InlineData(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	cmd := evalFlagSet(t)
	cmd.Flags().Set("data", `{"status":"active"}`)

	stubExit(t)
	_, _ = captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
}

func TestRunEval_StdinInput(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})

	restore := replaceStdin(t, `{"status":"active"}`)
	defer restore()

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", "-")

	stubExit(t)
	_, _ = captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval stdin: %v", err)
		}
	})
}

func TestRunEval_NamespaceFilter(t *testing.T) {
	newTestServer(t,
		policyFixture{"pass-policy", "default", testPassPolicy},
		policyFixture{"security-check", "security", testSecurityPolicy},
	)
	input := writeTempFile(t, "in.json", `{"status":"active","tls":true}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)
	cmd.Flags().Set("namespace", "security")

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})
	if !strings.Contains(stdout, "security") && !strings.Contains(stdout, "ALLOW") {
		t.Errorf("expected security output; got %q", stdout)
	}
}

func TestRunEval_BadServerURL(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	// Point CLI at a closed port.
	viperSetServer(t, "http://127.0.0.1:1")

	input := writeTempFile(t, "in.json", `{"status":"active"}`)
	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	stubExit(t)
	err := runEval(cmd, nil)
	if err == nil {
		t.Error("expected error from unreachable server")
	}
}

func TestRunEval_MissingInput(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	cmd := evalFlagSet(t)
	// No --input, no --data.

	stubExit(t)
	err := runEval(cmd, nil)
	if err == nil {
		t.Error("expected error when neither --input nor --data set")
	}
}

func TestRunEval_BadJSONInline(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	cmd := evalFlagSet(t)
	cmd.Flags().Set("data", `not json`)

	stubExit(t)
	err := runEval(cmd, nil)
	if err == nil {
		t.Error("expected parse error")
	}
}

func TestRunEval_VerboseAndTraceFlags(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.json", `{"status":"active"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)
	cmd.Flags().Set("verbose", "true")
	cmd.Flags().Set("trace", "true")
	cmd.Flags().Set("request-id", "req-test-123")
	cmd.Flags().Set("policy", "default/pass-policy")

	stubExit(t)
	_, _ = captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
}

func TestRunEval_Verbose_ShowsDetailsOnPass(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.json", `{"status":"active"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)
	cmd.Flags().Set("verbose", "true")

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
	if !strings.Contains(stdout, "PASS") || !strings.Contains(stdout, "SEVERITY") {
		t.Errorf("expected rule table with PASS row when --verbose=true on allow; got %q", stdout)
	}
}

func TestRunEval_Default_HidesDetailsOnPass(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.json", `{"status":"active"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("expected ALLOW decision; got %q", stdout)
	}
	if strings.Contains(stdout, "SEVERITY") {
		t.Errorf("expected no rule table on pass by default; got %q", stdout)
	}
}

func TestRunEval_Default_ShowsDetailsOnFail(t *testing.T) {
	newTestServer(t, policyFixture{"deny-policy", "default", testDenyPolicy})
	input := writeTempFile(t, "in.json", `{"env":"staging"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})
	if !strings.Contains(stdout, "FAIL") || !strings.Contains(stdout, "SEVERITY") {
		t.Errorf("expected rule table on fail by default; got %q", stdout)
	}
}

func TestRunEval_VerboseFalse_HidesDetailsOnFail(t *testing.T) {
	newTestServer(t, policyFixture{"deny-policy", "default", testDenyPolicy})
	input := writeTempFile(t, "in.json", `{"env":"staging"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)
	cmd.Flags().Set("verbose", "false")

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		_ = runEval(cmd, nil)
	})
	if !strings.Contains(stdout, "DENY") {
		t.Errorf("expected DENY decision still visible; got %q", stdout)
	}
	if strings.Contains(stdout, "SEVERITY") || strings.Contains(stdout, "FAIL") {
		t.Errorf("expected rule table suppressed with --verbose=false; got %q", stdout)
	}
}

func TestRunEval_YAMLFormatInput(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.yaml", "status: active\n")

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)
	cmd.Flags().Set("format", "yaml")

	stubExit(t)
	_, _ = captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
}

func TestRunEval_AutoFormatYAMLFile(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.yaml", "status: active\n")

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)

	stubExit(t)
	_, _ = captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
}

func TestRunEval_QuietOutput(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	input := writeTempFile(t, "in.json", `{"status":"active"}`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", input)
	cmd.Flags().Set("quiet", "true")

	stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval: %v", err)
		}
	})
	if strings.Contains(stdout, "Decision:") {
		t.Errorf("expected quiet output, got %q", stdout)
	}
}

// Verify the Evaluate result integrates with output helpers directly.
func TestOutputHelpers(t *testing.T) {
	result := &client.EvaluateResult{
		Decision: "deny",
		Results: []client.RuleResult{{
			PolicyName: "x", PolicyNamespace: "y", RuleID: "r1",
			Severity: "high", Passed: false, Message: "nope",
		}},
		Metrics: client.Metrics{PoliciesEvaluated: 1, RulesEvaluated: 1, EvaluationTimeNs: 100},
	}

	if out := mustCapture(t, func() { _ = outputJSON(result) }); !strings.Contains(out, `"decision"`) {
		t.Errorf("outputJSON: %q", out)
	}
	if out := mustCapture(t, func() { _ = outputYAML(result) }); !strings.Contains(out, "decision:") {
		t.Errorf("outputYAML: %q", out)
	}
	if out := mustCapture(t, func() { _ = outputTable(result, false, false) }); !strings.Contains(out, "DENY") {
		t.Errorf("outputTable: %q", out)
	}
	if out := mustCapture(t, func() { _ = outputTable(result, true, false) }); strings.Contains(out, "Decision:") {
		t.Errorf("outputTable quiet still printed header: %q", out)
	}
	if out := mustCapture(t, func() { _ = outputTable(result, false, true) }); strings.Contains(out, "SEVERITY") {
		t.Errorf("outputTable suppressDetails still printed table: %q", out)
	}
}

func TestRunEval_StdinBadJSON(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	restore := replaceStdin(t, `not json`)
	defer restore()

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", "-")

	stubExit(t)
	err := runEval(cmd, nil)
	if err == nil {
		t.Error("expected stdin parse error")
	}
}

func TestRunEval_JSONFormatFileBadContent(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})
	path := writeTempFile(t, "bad.json", `not json`)

	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", path)
	cmd.Flags().Set("format", "json")

	stubExit(t)
	err := runEval(cmd, nil)
	if err == nil {
		t.Error("expected parse error")
	}
}

func TestReadInput_MissingFile(t *testing.T) {
	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", "/nope/nope.json")
	_, err := readInput(cmd)
	if err == nil {
		t.Error("expected error on missing file")
	}
}

func TestReadInput_BadFormat(t *testing.T) {
	cmd := evalFlagSet(t)
	cmd.Flags().Set("format", "toml")
	_, err := readInput(cmd)
	if err == nil {
		t.Error("expected error on unknown format")
	}
}

func TestReadInput_SpecifiedFormatJSON(t *testing.T) {
	path := writeTempFile(t, "in.data", `{"k":"v"}`)
	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", path)
	cmd.Flags().Set("format", "json")
	m, err := readInput(cmd)
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}
	if m["k"] != "v" {
		t.Errorf("unexpected: %v", m)
	}
}

func TestReadInput_SpecifiedFormatBadJSON(t *testing.T) {
	path := writeTempFile(t, "in.data", `not json`)
	cmd := evalFlagSet(t)
	cmd.Flags().Set("input", path)
	cmd.Flags().Set("format", "json")
	_, err := readInput(cmd)
	if err == nil {
		t.Error("expected parse error")
	}
}

// Long policy names / messages should be truncated in the table.
func TestOutputTableTruncation(t *testing.T) {
	long := strings.Repeat("a", 60)
	result := &client.EvaluateResult{
		Decision: "allow",
		Results: []client.RuleResult{{
			PolicyName: long, PolicyNamespace: "ns", RuleID: "r1",
			Severity: "low", Passed: true, Message: long,
		}},
	}
	out := mustCapture(t, func() { _ = outputTable(result, false, false) })
	if !strings.Contains(out, "...") {
		t.Errorf("expected truncation marker in %q", out)
	}
}
