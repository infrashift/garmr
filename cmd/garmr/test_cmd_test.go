package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const runTestSuiteCUE = `
policy: "pass-policy"

tests: [
	{
		name: "active input is allowed"
		input: {kind: "thing", status: "active"}
		expect: decision: "allow"
	},
	{
		name: "inactive input is denied"
		input: {kind: "thing", status: "inactive"}
		expect: decision: "deny"
	},
]
`

// runTestFlags resets the package-level flag state runTest reads and returns
// a command carrying the persistent flags it looks up.
func runTestFlags(t *testing.T) *cobraCmd {
	t.Helper()
	prevRecursive, prevFilter, prevOutput, prevFailFast := testRecursive, testFilter, testOutput, testFailFast
	t.Cleanup(func() {
		testRecursive, testFilter, testOutput, testFailFast = prevRecursive, prevFilter, prevOutput, prevFailFast
	})
	testRecursive, testFilter, testOutput, testFailFast = false, "", "text", false
	return newTestCmd(t, flagSpec{Kind: "bool", Name: "verbose"})
}

// writeTestPair writes a policy file and its sibling _test.cue into a temp
// dir and returns both paths.
func writeTestPair(t *testing.T, suite string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "p.cue")
	testPath := filepath.Join(dir, "p_test.cue")
	if err := os.WriteFile(policyPath, []byte(testDirPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testPath, []byte(suite), 0644); err != nil {
		t.Fatal(err)
	}
	return policyPath, testPath
}

func TestRunTest_PassingSuite(t *testing.T) {
	policyPath, testPath := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)

	stdout, _ := captureOutput(t, func() {
		if err := runTest(cmd, []string{policyPath, testPath}); err != nil {
			t.Fatalf("runTest: %v", err)
		}
	})
	if !strings.Contains(stdout, "active input is allowed") && !strings.Contains(stdout, "2 passed") {
		t.Errorf("expected pass output, got %q", stdout)
	}
}

func TestRunTest_ImplicitTestFileDiscovery(t *testing.T) {
	policyPath, _ := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)

	// Only the policy file is named; the sibling p_test.cue must be found.
	_, _ = captureOutput(t, func() {
		if err := runTest(cmd, []string{policyPath}); err != nil {
			t.Fatalf("runTest with implicit discovery: %v", err)
		}
	})
}

func TestRunTest_DirectoryArg(t *testing.T) {
	policyPath, _ := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)

	_, _ = captureOutput(t, func() {
		if err := runTest(cmd, []string{filepath.Dir(policyPath)}); err != nil {
			t.Fatalf("runTest on directory: %v", err)
		}
	})
}

func TestRunTest_FailingExpectation(t *testing.T) {
	// Expect deny for an input the policy allows: the suite must fail.
	suite := `
policy: "pass-policy"

tests: [
	{
		name: "wrong expectation"
		input: {kind: "thing", status: "active"}
		expect: decision: "deny"
	},
]
`
	policyPath, testPath := writeTestPair(t, suite)
	cmd := runTestFlags(t)

	var err error
	_, _ = captureOutput(t, func() {
		err = runTest(cmd, []string{policyPath, testPath})
	})
	if err == nil || !strings.Contains(err.Error(), "test(s) failed") {
		t.Fatalf("expected a failed-tests error, got %v", err)
	}
}

func TestRunTest_NoTestFiles(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "p.cue")
	if err := os.WriteFile(policyPath, []byte(testDirPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := runTestFlags(t)

	var err error
	_, _ = captureOutput(t, func() {
		err = runTest(cmd, []string{policyPath})
	})
	if err == nil || !strings.Contains(err.Error(), "no test files found") {
		t.Fatalf("expected no-test-files error, got %v", err)
	}
}

func TestRunTest_FilterExcludesEverything(t *testing.T) {
	policyPath, testPath := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)
	testFilter = "matches-nothing"

	// Every case filtered out: the run completes without failures.
	_, _ = captureOutput(t, func() {
		if err := runTest(cmd, []string{policyPath, testPath}); err != nil {
			t.Fatalf("runTest with excluding filter: %v", err)
		}
	})
}

func TestRunTest_FilterSelectsOne(t *testing.T) {
	policyPath, testPath := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)
	testFilter = "inactive"

	stdout, _ := captureOutput(t, func() {
		if err := runTest(cmd, []string{policyPath, testPath}); err != nil {
			t.Fatalf("runTest with filter: %v", err)
		}
	})
	if strings.Contains(stdout, "active input is allowed") {
		t.Errorf("filtered-out test appears in output: %q", stdout)
	}
}

func TestRunTest_TAPOutput(t *testing.T) {
	policyPath, testPath := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)
	testOutput = "tap"

	stdout, _ := captureOutput(t, func() {
		if err := runTest(cmd, []string{policyPath, testPath}); err != nil {
			t.Fatalf("runTest tap: %v", err)
		}
	})
	if !strings.Contains(stdout, "TAP version") && !strings.Contains(stdout, "ok 1") {
		t.Errorf("expected TAP output, got %q", stdout)
	}
}

func TestRunTest_JSONOutput(t *testing.T) {
	policyPath, testPath := writeTestPair(t, runTestSuiteCUE)
	cmd := runTestFlags(t)
	testOutput = "json"

	stdout, _ := captureOutput(t, func() {
		if err := runTest(cmd, []string{policyPath, testPath}); err != nil {
			t.Fatalf("runTest json: %v", err)
		}
	})
	if !strings.Contains(stdout, `"passed"`) {
		t.Errorf("expected JSON results, got %q", stdout)
	}
}
