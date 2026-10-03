package engine

import (
	"context"
	"os"
	"testing"
)

// A failed load must leave the published set exactly as it was: loads build
// a new set and publish it only once everything compiled.

func TestLoadPolicy_FailureLeavesSetUnchanged(t *testing.T) {
	eng := newTestEngine(t)
	good := makePolicy("good", "default", "valid",
		`{id: "r1", description: "d", severity: "high", expr: {match: {path: "x", equals: 1}}}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "good", "default", good); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	before := eng.PolicySetDigest()

	bad := makePolicy("bad", "default", "invalid",
		`{id: "r1", description: "d", severity: "NOT-A-SEVERITY", expr: {match: {path: "x", equals: 1}}}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "bad", "default", bad); err == nil {
		t.Fatal("LoadPolicy succeeded on an invalid policy; the test needs a policy that fails")
	}

	if got := eng.ListPolicies(""); len(got) != 1 {
		t.Errorf("ListPolicies returned %d policies after a failed load, want 1", len(got))
	}
	if eng.PolicySetDigest() != before {
		t.Error("digest changed after a failed load")
	}
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"x": 2.0}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("decision = %v, want %v from the surviving policy", resp.Decision, DecisionDeny)
	}
}

func TestLoadPoliciesFromFile_FailureLeavesSetUnchanged(t *testing.T) {
	eng := newTestEngine(t)

	dir := t.TempDir()
	path := dir + "/broken.cue"
	if err := writeTestFile(path, "package policies\n{{{ not cue\n"); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if _, err := eng.LoadPoliciesFromFile(context.Background(), path); err == nil {
		t.Fatal("LoadPoliciesFromFile succeeded on an unparseable file")
	}
	if got := eng.ListPolicies(""); len(got) != 0 {
		t.Errorf("ListPolicies returned %d policies after a failed load, want 0", len(got))
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
