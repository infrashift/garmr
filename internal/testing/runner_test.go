package testing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPolicyFile = `package policies

testPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "replica-cap"
		namespace: "quality"
	}
	spec: {
		description: "replica cap"
		target: resources: [{kind: "Deployment"}]
		rules: [{
			id:          "CAP-001"
			description: "replicas must be at most 3"
			severity:    "high"
			expr: match: {path: "spec.replicas", lessThanOrEqual: 3}
			message: "too many replicas"
		}]
		enforcement: action: "deny"
	}
}
`

func newRunnerWithPolicy(t *testing.T) *Runner {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cue")
	if err := os.WriteFile(path, []byte(testPolicyFile), 0644); err != nil {
		t.Fatal(err)
	}

	r, err := NewRunner(false)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	if err := r.LoadPolicyFile(path); err != nil {
		t.Fatalf("LoadPolicyFile: %v", err)
	}
	return r
}

func TestRunner_DecisionsComeFromRealEngine(t *testing.T) {
	r := newRunnerWithPolicy(t)

	suite, err := r.LoadTestSuite(`
policy: "replica-cap"
tests: [
	{
		name: "within cap"
		input: {kind: "Deployment", spec: replicas: 2}
		expect: {decision: "allow", noViolations: true}
	},
	{
		name: "over cap"
		input: {kind: "Deployment", spec: replicas: 5}
		expect: {
			decision: "deny"
			violations: [{id: "CAP-001", severity: "high", messageContains: "too many"}]
			violationCount: 1
		}
	},
]
`)
	if err != nil {
		t.Fatalf("LoadTestSuite: %v", err)
	}

	result := r.RunSuite(context.Background(), suite)
	if result.Passed != 2 || result.Failed != 0 {
		t.Fatalf("expected 2 passed, got %+v", result.Results)
	}
}

func TestRunner_WrongExpectationFails(t *testing.T) {
	// The old harness never produced violations, so decision assertions
	// trivially passed. Prove a wrong expectation now fails.
	r := newRunnerWithPolicy(t)

	suite, err := r.LoadTestSuite(`
policy: "replica-cap"
tests: [{
	name: "wrong expectation"
	input: {kind: "Deployment", spec: replicas: 5}
	expect: decision: "allow"
}]
`)
	if err != nil {
		t.Fatalf("LoadTestSuite: %v", err)
	}

	result := r.RunSuite(context.Background(), suite)
	if result.Failed != 1 {
		t.Fatalf("expected 1 failure, got %+v", result.Results)
	}
	if !strings.Contains(result.Results[0].Failures[0], `expected decision "allow", got "deny"`) {
		t.Errorf("unexpected failure message: %v", result.Results[0].Failures)
	}
}

func TestRunner_QualifiedAndUnqualifiedPolicyNames(t *testing.T) {
	r := newRunnerWithPolicy(t)

	for _, ref := range []string{"replica-cap", "quality/replica-cap"} {
		suite, err := r.LoadTestSuite(`
policy: "` + ref + `"
tests: [{
	name: "resolves"
	input: {kind: "Deployment", spec: replicas: 1}
	expect: decision: "allow"
}]
`)
		if err != nil {
			t.Fatalf("LoadTestSuite: %v", err)
		}
		result := r.RunSuite(context.Background(), suite)
		if result.Passed != 1 {
			t.Errorf("policy ref %q: expected pass, got %+v", ref, result.Results[0].Failures)
		}
	}
}

func TestRunner_UnknownPolicyFails(t *testing.T) {
	r := newRunnerWithPolicy(t)

	suite, _ := r.LoadTestSuite(`
policy: "no-such-policy"
tests: [{
	name: "cannot run"
	input: {kind: "Deployment"}
	expect: decision: "allow"
}]
`)
	result := r.RunSuite(context.Background(), suite)
	if result.Failed != 1 || !strings.Contains(result.Results[0].Failures[0], "policy not loaded") {
		t.Errorf("expected policy-not-loaded failure, got %+v", result.Results)
	}
}

func TestRunner_TargetMismatchSurfacesNoMatch(t *testing.T) {
	// Input the policy does not target: the engine fails closed and the
	// synthetic no-match result surfaces as a violation explaining why.
	r := newRunnerWithPolicy(t)

	suite, _ := r.LoadTestSuite(`
policy: "replica-cap"
tests: [{
	name: "wrong kind"
	input: {kind: "Pod"}
	expect: {
		decision: "deny"
		violations: [{id: "no-match"}]
	}
}]
`)
	result := r.RunSuite(context.Background(), suite)
	if result.Passed != 1 {
		t.Errorf("expected no-match assertion to pass, got %+v", result.Results[0].Failures)
	}
}

func TestRunner_SkippedTests(t *testing.T) {
	r := newRunnerWithPolicy(t)

	suite, _ := r.LoadTestSuite(`
policy: "replica-cap"
tests: [{
	name: "not ready"
	skip: true
	skipReason: "pending fixture"
	input: {kind: "Deployment"}
	expect: decision: "allow"
}]
`)
	result := r.RunSuite(context.Background(), suite)
	if result.Skipped != 1 || result.Failed != 0 {
		t.Errorf("expected 1 skipped, got %+v", result)
	}
}
