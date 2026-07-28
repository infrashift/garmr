package engine

import (
	"context"
	"errors"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestMutateAll_NoReplicaMutatedOnFailure is the unit-level contract:
// if any prepare fails, no commit runs.
//
// forEachExclusive could not give this guarantee — it applied fn to every
// replica and returned the first error, so replicas that already succeeded
// kept the mutation.
func TestMutateAll_NoReplicaMutatedOnFailure(t *testing.T) {
	set, err := newPolicySet(4)
	if err != nil {
		t.Fatalf("newPolicySet: %v", err)
	}

	wantErr := errors.New("prepare failed")
	var commits int

	err = set.mutateAll(func(i int, r *policyReplica) (func(), error) {
		if i == 2 {
			return nil, wantErr
		}
		return func() { commits++ }, nil
	})

	if !errors.Is(err, wantErr) {
		t.Errorf("mutateAll error = %v, want %v", err, wantErr)
	}
	if commits != 0 {
		t.Errorf("%d commits ran after a failed prepare; want 0", commits)
	}
}

func TestMutateAll_AllCommitsRunOnSuccess(t *testing.T) {
	const k = 4
	set, err := newPolicySet(k)
	if err != nil {
		t.Fatalf("newPolicySet: %v", err)
	}

	var commits int
	if err := set.mutateAll(func(i int, r *policyReplica) (func(), error) {
		return func() { commits++ }, nil
	}); err != nil {
		t.Fatalf("mutateAll: %v", err)
	}

	if commits != k {
		t.Errorf("%d commits ran, want %d (one per replica)", commits, k)
	}
}

// TestLoadPolicy_FailureLeavesAllReplicasConsistent is the behavioural
// version: after a failed load, every replica must agree. It evaluates far
// more times than there are replicas so the pool hands out each one.
func TestLoadPolicy_FailureLeavesAllReplicasConsistent(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// A policy that fails schema validation in every replica.
	bad := makePolicy("bad", "default", "invalid",
		`{id: "r1", description: "d", severity: "NOT-A-SEVERITY", expr: {match: {path: "x", equals: 1}}}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "bad", "default", bad); err == nil {
		t.Fatal("LoadPolicy succeeded on an invalid policy; the test needs a policy that fails")
	}

	// No replica may hold it.
	if got := eng.ListPolicies(""); len(got) != 0 {
		t.Errorf("ListPolicies returned %d policies after a failed load, want 0", len(got))
	}

	assertConsistentAcrossReplicas(t, eng, map[string]any{"x": 1.0})
}

// TestLoadPolicy_SuccessIsVisibleOnEveryReplica is the positive control: the
// staging change must not make loads invisible.
func TestLoadPolicy_SuccessIsVisibleOnEveryReplica(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	good := makePolicy("good", "default", "valid",
		`{id: "r1", description: "d", severity: "high", expr: {match: {path: "x", equals: 1}}}`,
		"deny", "")
	if loadErr := eng.LoadPolicy(context.Background(), "good", "default", good); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	assertConsistentAcrossReplicas(t, eng, map[string]any{"x": 2.0})

	// And the decision is the expected one, not merely consistent.
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"x": 2.0}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("decision = %v, want %v", resp.Decision, DecisionDeny)
	}
}

// TestLoadPoliciesFromFile_FailureLeavesAllReplicasConsistent covers the
// directory/file loader path, which stages into a pending map for the same
// reason.
func TestLoadPoliciesFromFile_FailureLeavesAllReplicasConsistent(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

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
	assertConsistentAcrossReplicas(t, eng, map[string]any{"x": 1.0})
}

// assertConsistentAcrossReplicas evaluates the same input many times. Because
// the pool hands out an arbitrary replica per evaluation, divergent replicas
// show up as differing decisions.
func assertConsistentAcrossReplicas(t *testing.T, eng *Engine, input map[string]any) {
	t.Helper()

	const iterations = 64
	var first Decision
	for i := 0; i < iterations; i++ {
		resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
		if err != nil {
			t.Fatalf("evaluation %d failed: %v", i, err)
		}
		if i == 0 {
			first = resp.Decision
			continue
		}
		if resp.Decision != first {
			t.Fatalf("evaluation %d returned %v but evaluation 0 returned %v: replicas have diverged",
				i, resp.Decision, first)
		}
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
