package main

import (
	"strings"
	"testing"

	"github.com/infrashift/garmr/internal/client"
)

// evalResultWithMode builds a result carrying evaluation-mode counts.
func evalResultWithMode(evaluated, inScope, skipped int) *client.EvaluateResult {
	r := &client.EvaluateResult{
		Decision: "deny",
		Results: []client.RuleResult{
			{PolicyNamespace: "ns", PolicyName: "p", RuleID: "R-001", Severity: "high", Passed: false, Message: "boom"},
		},
	}
	r.EvaluationMode.RulesEvaluated = evaluated
	r.EvaluationMode.TotalRulesInScope = inScope
	r.EvaluationMode.RulesSkipped = skipped
	return r
}

// TestRunEval_DataFlagIsReachable covers the flag that could never be used:
// --input was marked required, so `garmr eval --data '{...}'` failed with
// `required flag(s) "input" not set` before readInput ever checked --data.
func TestRunEval_DataFlagIsReachable(t *testing.T) {
	newTestServer(t, policyFixture{"pass-policy", "default", testPassPolicy})

	cmd := evalFlagSet(t)
	cmd.Flags().Set("data", `{"status":"active"}`)

	rec := stubExit(t)
	stdout, _ := captureOutput(t, func() {
		if err := runEval(cmd, nil); err != nil {
			t.Fatalf("runEval with --data: %v", err)
		}
	})

	if rec.Called {
		t.Errorf("did not expect exit; got %d", rec.Code)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("missing ALLOW in output: %q", stdout)
	}
}

// TestRunEval_RequiresInputOrData replaces the old cobra required-flag error
// with one that names both ways of supplying input.
func TestRunEval_RequiresInputOrData(t *testing.T) {
	newTestServer(t)

	cmd := evalFlagSet(t)

	stubExit(t)
	var err error
	captureOutput(t, func() {
		err = runEval(cmd, nil)
	})

	if err == nil {
		t.Fatal("runEval with neither --input nor --data succeeded")
	}
	if !strings.Contains(err.Error(), "one of --input or --data is required") {
		t.Errorf("error = %v, want it to name both flags", err)
	}
}

// TestOutputTable_ReportsSkippedRules verifies the CLI surfaces the
// evaluation-mode counts the engine computes. `garmr eval --help` promises
// them, and until now nothing printed them.
func TestOutputTable_ReportsSkippedRules(t *testing.T) {
	result := evalResultWithMode(3, 10, 7)

	out := mustCapture(t, func() { _ = outputTable(result, false, false) })
	if !strings.Contains(out, "Evaluated 3 of 10 rules (7 skipped)") {
		t.Errorf("output does not report skipped rules:\n%s", out)
	}
}

func TestOutputTable_ReportsEarlyTermination(t *testing.T) {
	result := evalResultWithMode(1, 5, 4)
	result.TerminatedEarly = true
	result.TerminationRule = &client.RuleResult{
		PolicyNamespace: "security",
		PolicyName:      "container-security",
		RuleID:          "SEC-001",
	}

	out := mustCapture(t, func() { _ = outputTable(result, false, false) })
	if !strings.Contains(out, "Terminated early at security/container-security#SEC-001") {
		t.Errorf("output does not name the terminating rule:\n%s", out)
	}
}

func TestOutputTable_ReportsDryRun(t *testing.T) {
	result := evalResultWithMode(2, 2, 0)
	result.EvaluationMode.DryRun = true

	out := mustCapture(t, func() { _ = outputTable(result, false, false) })
	if !strings.Contains(out, "Dry run") {
		t.Errorf("output does not report dry-run mode:\n%s", out)
	}
}

// TestOutputTable_QuietSuppressesModeLines keeps -q meaning quiet.
func TestOutputTable_QuietSuppressesModeLines(t *testing.T) {
	result := evalResultWithMode(1, 5, 4)
	result.TerminatedEarly = true

	out := mustCapture(t, func() { _ = outputTable(result, true, false) })
	if strings.Contains(out, "skipped") || strings.Contains(out, "Terminated early") {
		t.Errorf("quiet output still prints mode lines:\n%s", out)
	}
}

// TestSubcommandsDoNotShadowRootFlags guards the root -o/--output and
// -v/--verbose persistent flags. `garmr test` used to redeclare -o with a
// different value space (text|json|tap vs table|json|yaml), so
// `garmr test -o table` was silently invalid.
func TestSubcommandsDoNotShadowRootFlags(t *testing.T) {
	for _, name := range []string{"output", "verbose"} {
		if f := testCmd.Flags().Lookup(name); f != nil && f.Shorthand != "" {
			t.Errorf("testCmd redeclares -%s/--%s, shadowing the root persistent flag", f.Shorthand, name)
		}
	}
	if f := docsGenerateCmd.Flags().Lookup("output"); f != nil {
		t.Error("docsGenerateCmd declares --output; it should be --out-dir so the root -o is not shadowed")
	}
	if docsGenerateCmd.Flags().Lookup("out-dir") == nil {
		t.Error("docsGenerateCmd is missing --out-dir")
	}
	if testCmd.Flags().Lookup("format") == nil {
		t.Error("testCmd is missing --format")
	}
}

// TestRemovedFlagsAreGone pins the flags that were declared and never read.
func TestRemovedFlagsAreGone(t *testing.T) {
	cases := []struct {
		cmdName string
		lookup  func(string) bool
		flag    string
		why     string
	}{
		{"policy list", func(n string) bool { return policyListCmd.Flags().Lookup(n) != nil }, "label", "nothing reads it"},
		{"policy reload", func(n string) bool { return policyReloadCmd.Flags().Lookup(n) != nil }, "force", "nothing reads it"},
		{"docs generate", func(n string) bool { return docsGenerateCmd.Flags().Lookup(n) != nil }, "author", "no template reads it"},
		{"eval", func(n string) bool { return evalCmd.Flags().Lookup(n) != nil }, "trace", "it always returned an empty result"},
	}

	for _, c := range cases {
		if c.lookup(c.flag) {
			t.Errorf("%s still declares --%s (%s)", c.cmdName, c.flag, c.why)
		}
	}

	// policy delete --force IS read by runPolicyDelete, so it must stay.
	if policyDeleteCmd.Flags().Lookup("force") == nil {
		t.Error("policy delete --force was removed, but runPolicyDelete reads it")
	}
}
