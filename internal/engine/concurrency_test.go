package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeReplicaLimitPolicy writes a one-rule policy to a fresh directory for
// the concurrency tests below.
func writeReplicaLimitPolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := `package policies

replicaLimit: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "replica-limit"
		namespace: "default"
	}
	spec: {
		description: "replica limit"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "REP-001"
			description: "replicas must be at most 3"
			severity:    "high"
			expr: match: {path: "spec.replicas", lessThanOrEqual: 3}
		}]
		enforcement: action: "deny"
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(src), 0644); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return dir
}

// TestEvaluate_DirLoad_Concurrent loads a policy via the directory path and
// hammers it from many goroutines with alternating pass/fail inputs. Every
// decision must match its input. Run with -race to catch shared state in the
// evaluator.
func TestEvaluate_DirLoad_Concurrent(t *testing.T) {
	eng := newTestEngine(t)
	dir := writeReplicaLimitPolicy(t)

	if _, err := eng.ReloadPoliciesFromDir(context.Background(), dir); err != nil {
		t.Fatalf("ReloadPoliciesFromDir failed: %v", err)
	}

	const workers = 16
	const iters = 30

	var wg sync.WaitGroup
	errs := make(chan error, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				replicas := 2
				want := DecisionAllow
				if (w+i)%2 == 0 {
					replicas = 5
					want = DecisionDeny
				}
				resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
					Input: map[string]any{
						"kind": "Deployment",
						"spec": map[string]any{"replicas": replicas},
					},
				})
				if err != nil {
					errs <- fmt.Errorf("worker %d iter %d: %w", w, i, err)
					continue
				}
				if resp.Decision != want {
					errs <- fmt.Errorf("worker %d iter %d: replicas=%d want %s got %s", w, i, replicas, want, resp.Decision)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestReloadDuringEvaluation reloads the policy set while evaluations are in
// flight. In-flight evaluations must complete on the old set; every response
// must be internally consistent and error-free.
func TestReloadDuringEvaluation(t *testing.T) {
	eng := newTestEngine(t)
	dir := writeReplicaLimitPolicy(t)

	if _, err := eng.ReloadPoliciesFromDir(context.Background(), dir); err != nil {
		t.Fatalf("initial reload failed: %v", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Reloader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if _, err := eng.ReloadPoliciesFromDir(context.Background(), dir); err != nil {
				t.Errorf("reload failed: %v", err)
			}
		}
		close(done)
	}()

	// Evaluator goroutines
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
					Input: map[string]any{
						"kind": "Deployment",
						"spec": map[string]any{"replicas": 5},
					},
				})
				if err != nil {
					t.Errorf("evaluate failed during reload: %v", err)
					return
				}
				if resp.Decision != DecisionDeny {
					t.Errorf("expected deny for replicas=5, got %s", resp.Decision)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestValidate_ConcurrentWithEvaluate races Validate against Evaluate.
func TestValidate_ConcurrentWithEvaluate(t *testing.T) {
	source := makePolicy("val-race", "default", "race",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "kind", equals: "Pod"}}}`,
		"deny", "")
	eng := loadTestPolicy(t, "val-race", "default", source)

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if errs, _ := eng.Validate(source); len(errs) != 0 {
					t.Errorf("valid policy reported errors: %v", errs)
					return
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := eng.Evaluate(context.Background(), &EvaluateRequest{
					Input: map[string]any{"kind": "Pod"},
				}); err != nil {
					t.Errorf("evaluate failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestEvaluate_DryRunDoesNotDowngradeEnforcingDeny loads one enforcing deny
// policy and one dry-run deny policy that both fail, in both sort orders. The
// overall decision must stay Deny regardless of evaluation order.
func TestEvaluate_DryRunDoesNotDowngradeEnforcingDeny(t *testing.T) {
	failingRule := `{id: "r1", description: "always fails", severity: "high", expr: {match: {path: "kind", equals: "NoSuchKind"}}}`

	cases := []struct {
		name      string
		enforcing string
		dryRun    string
	}{
		// Policies evaluate in sorted key order, so cover the dry-run
		// policy landing both before and after the enforcing one.
		{"dry-run-first", "z-enforce", "a-dryrun"},
		{"dry-run-last", "a-enforce", "z-dryrun"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newTestEngine(t)
			ctx := context.Background()

			enforcing := makePolicy(tc.enforcing, "default", "enforcing deny", failingRule, "deny", "")
			if err := eng.LoadPolicy(ctx, tc.enforcing, "default", enforcing); err != nil {
				t.Fatalf("loading enforcing policy: %v", err)
			}
			dryRun := makePolicyFull(tc.dryRun, "default", "dry-run deny", failingRule, "deny", "dryRun: true", "")
			if err := eng.LoadPolicy(ctx, tc.dryRun, "default", dryRun); err != nil {
				t.Fatalf("loading dry-run policy: %v", err)
			}

			resp, err := eng.Evaluate(ctx, &EvaluateRequest{
				Input: map[string]any{"kind": "Pod"},
			})
			if err != nil {
				t.Fatalf("evaluate failed: %v", err)
			}
			if resp.Decision != DecisionDeny {
				t.Errorf("dry-run policy downgraded enforcing deny: got %s", resp.Decision)
			}
			if !resp.EvaluationMode.DryRun {
				t.Error("expected DryRun mode flag to be set")
			}
		})
	}
}

// TestEvaluate_Deterministic verifies repeated evaluations over a multi-policy
// set produce identical result ordering.
func TestEvaluate_Deterministic(t *testing.T) {
	eng := newTestEngine(t)
	ctx := context.Background()

	failingRule := `{id: "r1", description: "always fails", severity: "low", expr: {match: {path: "kind", equals: "NoSuchKind"}}}`
	for _, name := range []string{"pol-c", "pol-a", "pol-e", "pol-b", "pol-d"} {
		src := makePolicy(name, "default", "det", failingRule, "warn", "")
		if err := eng.LoadPolicy(ctx, name, "default", src); err != nil {
			t.Fatalf("loading %s: %v", name, err)
		}
	}

	var first []string
	for i := 0; i < 5; i++ {
		resp, err := eng.Evaluate(ctx, &EvaluateRequest{Input: map[string]any{"kind": "Pod"}})
		if err != nil {
			t.Fatalf("evaluate failed: %v", err)
		}
		var order []string
		for _, r := range resp.Results {
			order = append(order, r.PolicyName)
		}
		if i == 0 {
			first = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(first, ",") {
			t.Fatalf("result order changed between runs: %v vs %v", first, order)
		}
	}
}
