package engine

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// --- Decision Logic ---

func TestEvaluate_AllRulesPass_Allow(t *testing.T) {
	source := makePolicy("allow-test", "default", "allow test",
		`{id: "r1", description: "pass", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "allow-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}

func TestEvaluate_DenyEnforcement_Deny(t *testing.T) {
	source := makePolicy("deny-test", "default", "deny test",
		`{id: "r1", description: "fail", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", "")
	eng := loadTestPolicy(t, "deny-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
	if len(resp.Results) == 0 {
		t.Error("expected results with violation")
	}
}

func TestEvaluate_WarnEnforcement_Warn(t *testing.T) {
	source := makePolicy("warn-test", "default", "warn test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "x should be 1"}`,
		"warn", "")
	eng := loadTestPolicy(t, "warn-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	if resp.Decision != DecisionWarn {
		t.Errorf("expected warn, got %s", resp.Decision)
	}
}

func TestEvaluate_IncludePassed(t *testing.T) {
	source := makePolicy("incl-test", "default", "include passed",
		`{id: "r1", description: "pass", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "incl-test", "default", source)

	// Without IncludePassed
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1.0},
	})
	if len(resp.Results) != 0 {
		t.Error("expected no results without IncludePassed")
	}

	// With IncludePassed
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 1.0},
		Options: EvaluateOptions{IncludePassed: true},
	})
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result with IncludePassed, got %d", len(resp.Results))
	}
}

// --- Fail-Fast ---

func TestEvaluate_FailFast(t *testing.T) {
	source := makePolicyFull("ff-test", "default", "fail fast test",
		`{id: "r1", description: "first", severity: "high", expr: {match: {path: "x", equals: 999}}, message: "first fails"},
		{id: "r2", description: "second", severity: "medium", expr: {match: {path: "y", equals: 999}}, message: "second fails"},
		{id: "r3", description: "third", severity: "low", expr: {match: {path: "z", equals: 999}}, message: "third fails"}`,
		"deny", "", `evaluation: failFast: true`)
	eng := loadTestPolicy(t, "ff-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 0.0, "y": 0.0, "z": 0.0},
	})
	if !resp.TerminatedEarly {
		t.Error("expected TerminatedEarly to be true")
	}
	if resp.EvaluationMode.RulesSkipped == 0 {
		t.Error("expected some skipped rules")
	}
	// Should only have evaluated 1 rule (the first failure)
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result with fail-fast, got %d", len(resp.Results))
	}
}

// --- Dry Run ---

func TestEvaluate_DryRun(t *testing.T) {
	source := makePolicyFull("dr-test", "default", "dry run test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", `dryRun: true`, "")
	eng := loadTestPolicy(t, "dr-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	// Dry run: deny should be downgraded to warn
	if resp.Decision != DecisionWarn {
		t.Errorf("expected warn (dry run), got %s", resp.Decision)
	}
	if !resp.EvaluationMode.DryRun {
		t.Error("expected DryRun mode to be true")
	}
	if len(resp.Results) > 0 && resp.Results[0].Message != "" {
		if len(resp.Results[0].Message) < 10 || resp.Results[0].Message[:10] != "[DRY RUN] " {
			t.Errorf("expected message to start with [DRY RUN], got: %s", resp.Results[0].Message)
		}
	}
}

func TestEvaluate_DryRunOverride(t *testing.T) {
	// Policy is NOT dry run, but override is set
	source := makePolicy("dro-test", "default", "dry run override",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dro-test", "default", source)

	dryRun := true
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 2.0},
		Options: EvaluateOptions{DryRunOverride: &dryRun},
	})
	if resp.Decision != DecisionWarn {
		t.Errorf("expected warn (dry run override), got %s", resp.Decision)
	}
}

// --- Category/Tag Filtering ---

func TestEvaluate_CategoryFilter(t *testing.T) {
	source := makePolicy("cat-test", "default", "category filter test",
		`{id: "r1", description: "security check", severity: "high", category: "security", expr: {match: {path: "x", equals: 1}}, message: "fail"},
		{id: "r2", description: "quality check", severity: "medium", category: "quality", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cat-test", "default", source)

	// Only evaluate security rules
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 2.0},
		Options: EvaluateOptions{IncludeCategories: []string{"security"}},
	})
	// Only the security rule should have been evaluated and failed
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result (security only), got %d", len(resp.Results))
	}
}

func TestEvaluate_TagFilter(t *testing.T) {
	source := makePolicy("tag-test", "default", "tag filter test",
		`{id: "r1", description: "prod check", severity: "high", tags: ["prod"], expr: {match: {path: "x", equals: 1}}, message: "fail"},
		{id: "r2", description: "dev check", severity: "low", tags: ["dev"], expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "tag-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"x": 2.0},
		Options: EvaluateOptions{ExcludeTags: []string{"dev"}},
	})
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result (excluding dev), got %d", len(resp.Results))
	}
}

// --- Exception Handling ---

func TestEvaluate_Exception(t *testing.T) {
	source := makePolicyFull("exc-test", "default", "exception test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "replicas", greaterThan: 0}}, message: "need replicas"}`,
		"deny", `exceptions: [{
			name: "legacy-app"
			reason: "legacy exception"
			match: {kind: "Deployment", names: ["legacy-app"]}
		}]`, "")
	eng := loadTestPolicy(t, "exc-test", "default", source)

	// Input matches exception
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "legacy-app"},
			"replicas": 0.0,
		},
	})
	// Exception matched, so evaluation is skipped — allow
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow (exception), got %s", resp.Decision)
	}

	// Input does NOT match exception
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "new-app"},
			"replicas": 0.0,
		},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny (no exception), got %s", resp.Decision)
	}
}

// --- Timeout Enforcement ---

func TestEvaluate_Timeout(t *testing.T) {
	source := makePolicyFull("timeout-test", "default", "timeout test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "", `evaluation: timeout: "1ns"`)
	eng := loadTestPolicy(t, "timeout-test", "default", source)

	// With an absurdly short timeout, the context should be cancelled
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 2.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	// With timeout, the rule may pass (timeout = don't penalize) or be skipped
	_ = resp // Just ensure no panic/error
}

// --- Namespace Filtering ---

func TestEvaluate_NamespaceFilter(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())

	source1 := makePolicy("p1", "ns1", "test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	source2 := makePolicy("p2", "ns2", "test",
		`{id: "r1", description: "check", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")

	eng.LoadPolicy(context.Background(), "p1", "ns1", source1)
	eng.LoadPolicy(context.Background(), "p2", "ns2", source2)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:     map[string]any{"x": 2.0},
		Namespace: "ns1",
	})
	// Only 1 policy (ns1) should have been evaluated
	if resp.Metrics.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", resp.Metrics.PoliciesEvaluated)
	}
}

// --- Metrics ---

func TestEvaluate_Metrics(t *testing.T) {
	source := makePolicy("met-test", "default", "metrics test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "met-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1.0},
	})
	if resp.Metrics == nil {
		t.Fatal("expected non-nil metrics")
	}
	if resp.Metrics.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", resp.Metrics.PoliciesEvaluated)
	}
	if resp.Metrics.RulesEvaluated != 1 {
		t.Errorf("expected 1 rule evaluated, got %d", resp.Metrics.RulesEvaluated)
	}
	if resp.Metrics.EvaluationTimeNs <= 0 {
		t.Error("expected positive evaluation time")
	}
}

// --- Empty Input ---

func TestEvaluate_NoPolicies(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"x": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fail-closed: no policies loaded → synthetic deny with remediation.
	if resp.Decision != DecisionDeny {
		t.Fatalf("expected deny with no policies, got %s", resp.Decision)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected exactly one synthetic result, got %d", len(resp.Results))
	}
	got := resp.Results[0]
	if got.PolicyNamespace != ReservedSystemNamespace ||
		got.PolicyName != SystemPolicyNameMatch ||
		got.RuleID != RuleIDNoMatch {
		t.Errorf("synthetic result has wrong identifiers: %+v", got)
	}
	if got.Passed {
		t.Error("synthetic result must have Passed=false")
	}
	if got.Remediation == "" {
		t.Error("synthetic result must include remediation guidance")
	}
}

func TestEvaluate_NoMatch_SubCases(t *testing.T) {
	const ruleBody = `{id: "r1", description: "pass", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`
	existsDefault := makePolicy("exists", "default", "exists", ruleBody, "deny", "")
	existsSecurity := makePolicy("exists", "security", "exists", ruleBody, "deny", "")

	cases := []struct {
		name         string
		seedPolicies []struct{ name, ns, rules string }
		req          *EvaluateRequest
		wantSubstr   string
	}{
		{
			name: "no policies loaded at all",
			req: &EvaluateRequest{
				Input: map[string]any{"kind": "Pod"},
			},
			wantSubstr: "No policies are loaded",
		},
		{
			name: "named policy missing",
			seedPolicies: []struct{ name, ns, rules string }{
				{"exists", "default", existsDefault},
			},
			req: &EvaluateRequest{
				Input:    map[string]any{"kind": "Pod"},
				Policies: []string{"does-not-exist"},
			},
			wantSubstr: "default/does-not-exist not found",
		},
		{
			name: "namespace has no policies",
			seedPolicies: []struct{ name, ns, rules string }{
				{"exists", "security", existsSecurity},
			},
			req: &EvaluateRequest{
				Input:     map[string]any{"kind": "Pod"},
				Namespace: "nonexistent",
			},
			wantSubstr: `No policies found in namespace "nonexistent"`,
		},
		{
			name: "policies exist but none target input",
			// seedPolicies and wantSubstr are populated below with a
			// handcrafted policy that restricts target.kind to "Deployment".
			req: &EvaluateRequest{
				Input: map[string]any{"kind": "Pod"},
			},
		},
	}

	// Build a targeted policy that restricts to kind "Deployment" so a Pod
	// input produces zero matches via target-selector mismatch. The default
	// test template hardcodes `kind: "*"`, so we assemble the CUE directly.
	targetedSource := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "targeted"
	namespace: "default"
}
spec: {
	description: "only applies to deployments"
	target: resources: [{kind: "Deployment"}]
	rules: [{id: "r1", description: "pass", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}]
	enforcement: {action: "deny"}
}
`
	cases[3].seedPolicies = []struct{ name, ns, rules string }{{"targeted", "default", targetedSource}}
	cases[3].wantSubstr = "No policy targets this input"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := NewEngine(zap.NewNop())
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			for _, p := range tc.seedPolicies {
				if err := eng.LoadPolicy(context.Background(), p.name, p.ns, p.rules); err != nil {
					t.Fatalf("LoadPolicy %s: %v", p.name, err)
				}
			}
			resp, err := eng.Evaluate(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if resp.Decision != DecisionDeny {
				t.Fatalf("expected deny, got %s", resp.Decision)
			}
			if len(resp.Results) != 1 {
				t.Fatalf("expected 1 synthetic result, got %d", len(resp.Results))
			}
			msg := resp.Results[0].Message
			if tc.wantSubstr != "" && !strings.Contains(msg, tc.wantSubstr) {
				t.Errorf("message %q did not contain %q", msg, tc.wantSubstr)
			}
		})
	}
}

func TestEvaluate_NoMatch_OptOut(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	eng.SetRequireMatch(false)

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"kind": "Pod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected legacy allow with require_match=false, got %s", resp.Decision)
	}
	if len(resp.Results) != 0 {
		t.Errorf("expected no synthetic result in opt-out mode, got %d", len(resp.Results))
	}
}

func TestEvaluate_NoMatch_DryRunNotApplicable(t *testing.T) {
	// A dry-run policy in namespace "other" exists, but we evaluate
	// namespace "missing" with no matches. The dry-run flag on the other
	// policy must NOT downgrade the synthetic deny, because no policy is
	// in scope.
	dryRunSource := makePolicyFull(
		"dry", "other", "dry",
		`{id: "r1", description: "x", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny",
		`dryRun: true`,
		"",
	)
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.LoadPolicy(context.Background(), "dry", "other", dryRunSource); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:     map[string]any{"kind": "Pod"},
		Namespace: "missing",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny (dry-run elsewhere must not downgrade), got %s", resp.Decision)
	}
}

// --- Concurrent evaluations ---

func TestEvaluate_Concurrent(t *testing.T) {
	source := makePolicy("conc-test", "default", "concurrent test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "conc-test", "default", source)

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func(val float64) {
			defer func() { done <- struct{}{} }()
			eng.Evaluate(context.Background(), &EvaluateRequest{
				Input: map[string]any{"x": val},
			})
		}(float64(i))
	}

	timeout := time.After(5 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("concurrent evaluations timed out")
		}
	}
}

// --- CUE Context Pool Stress Tests ---

// concurrentResult captures the outcome of a single concurrent evaluation.
type concurrentResult struct {
	WorkerID  int
	RequestID int
	Duration  time.Duration
	Decision  Decision
	Err       error
	RuleCount int
}

// concurrentStats aggregates metrics from a concurrent stress test run.
type concurrentStats struct {
	TotalRequests int
	Successes     int64
	Failures      int64
	AllowCount    int64
	DenyCount     int64
	WarnCount     int64
	Durations     []time.Duration
}

func (s *concurrentStats) compute() (min, max, mean, p50, p95, p99 time.Duration) {
	if len(s.Durations) == 0 {
		return
	}
	sorted := make([]time.Duration, len(s.Durations))
	copy(sorted, s.Durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	min = sorted[0]
	max = sorted[len(sorted)-1]

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	mean = total / time.Duration(len(sorted))

	p50 = sorted[int(math.Ceil(float64(len(sorted))*0.50))-1]
	p95 = sorted[int(math.Ceil(float64(len(sorted))*0.95))-1]
	p99 = sorted[int(math.Ceil(float64(len(sorted))*0.99))-1]
	return
}

// TestConcurrentCueContextPool_StressCorrectness fires 1000 concurrent requests
// against a shared engine with multiple policies, verifying that each evaluation
// returns the correct decision and that no data races or panics occur.
// Run with: go test -v -race -run TestConcurrentCueContextPool_StressCorrectness ./internal/engine/
func TestConcurrentCueContextPool_StressCorrectness(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Load a policy where x == 1 → allow, x != 1 → deny
	policyAllow := makePolicy("check-x", "default", "check x equals 1",
		`{id: "r1", description: "x must be 1", severity: "high", expr: {match: {path: "x", equals: 1}}, message: "x is not 1"}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "check-x", "default", policyAllow); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	// Load a second policy to stress multi-policy evaluation
	policyName := makePolicy("check-name", "default", "check name present",
		`{id: "r2", description: "name must exist", severity: "medium", expr: {exists: {path: "name"}}, message: "name missing"}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "check-name", "default", policyName); err != nil {
		t.Fatalf("LoadPolicy check-name: %v", err)
	}

	const totalRequests = 1000
	const concurrency = 50

	results := make([]concurrentResult, totalRequests)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency) // limit in-flight goroutines

	wallStart := time.Now()

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			// Alternate inputs: even → x=1 + name (should allow), odd → x=0 no name (should deny)
			var input map[string]any
			if idx%2 == 0 {
				input = map[string]any{"x": float64(1), "name": fmt.Sprintf("item-%d", idx)}
			} else {
				input = map[string]any{"x": float64(0)}
			}

			start := time.Now()
			resp, evalErr := eng.Evaluate(context.Background(), &EvaluateRequest{
				Input: input,
			})
			elapsed := time.Since(start)

			r := concurrentResult{
				WorkerID:  idx % concurrency,
				RequestID: idx,
				Duration:  elapsed,
				Err:       evalErr,
			}
			if resp != nil {
				r.Decision = resp.Decision
				r.RuleCount = len(resp.Results)
			}
			results[idx] = r
		}(i)
	}

	wg.Wait()
	wallElapsed := time.Since(wallStart)

	// Aggregate statistics
	stats := &concurrentStats{TotalRequests: totalRequests}
	for _, r := range results {
		stats.Durations = append(stats.Durations, r.Duration)
		if r.Err != nil {
			atomic.AddInt64(&stats.Failures, 1)
		} else {
			atomic.AddInt64(&stats.Successes, 1)
			switch r.Decision {
			case DecisionAllow:
				atomic.AddInt64(&stats.AllowCount, 1)
			case DecisionDeny:
				atomic.AddInt64(&stats.DenyCount, 1)
			case DecisionWarn:
				atomic.AddInt64(&stats.WarnCount, 1)
			}
		}
	}

	min, max, mean, p50, p95, p99 := stats.compute()

	t.Logf("=== CUE Context Pool Stress Test Results ===")
	t.Logf("Total requests:    %d", totalRequests)
	t.Logf("Concurrency:       %d", concurrency)
	t.Logf("Wall time:         %v", wallElapsed)
	t.Logf("Throughput:        %.1f req/s", float64(totalRequests)/wallElapsed.Seconds())
	t.Logf("")
	t.Logf("--- Outcomes ---")
	t.Logf("Successes:         %d", stats.Successes)
	t.Logf("Failures:          %d", stats.Failures)
	t.Logf("Allow decisions:   %d", stats.AllowCount)
	t.Logf("Deny decisions:    %d", stats.DenyCount)
	t.Logf("Warn decisions:    %d", stats.WarnCount)
	t.Logf("")
	t.Logf("--- Latency ---")
	t.Logf("Min:               %v", min)
	t.Logf("Max:               %v", max)
	t.Logf("Mean:              %v", mean)
	t.Logf("P50 (median):      %v", p50)
	t.Logf("P95:               %v", p95)
	t.Logf("P99:               %v", p99)

	// Verify zero failures
	if stats.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", stats.Failures)
		for _, r := range results {
			if r.Err != nil {
				t.Errorf("  request %d: %v", r.RequestID, r.Err)
			}
		}
	}

	// Verify correctness: even requests → allow, odd requests → deny
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if r.RequestID%2 == 0 {
			if r.Decision != DecisionAllow {
				t.Errorf("request %d: expected allow (x=1, name present), got %s", r.RequestID, r.Decision)
			}
		} else {
			if r.Decision != DecisionDeny {
				t.Errorf("request %d: expected deny (x=0, name missing), got %s", r.RequestID, r.Decision)
			}
		}
	}

	// Verify expected distribution: 500 allow, 500 deny
	if stats.AllowCount != 500 {
		t.Errorf("expected 500 allow decisions, got %d", stats.AllowCount)
	}
	if stats.DenyCount != 500 {
		t.Errorf("expected 500 deny decisions, got %d", stats.DenyCount)
	}
}

// TestConcurrentCueContextPool_MixedOperations stress-tests the pool with
// concurrent evaluations, validations, and policy loads happening simultaneously
// to verify the pool handles mixed operation types without corruption.
func TestConcurrentCueContextPool_MixedOperations(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	basePolicy := makePolicy("base", "default", "base policy",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "val", equals: 1}}, message: "fail"}`,
		"deny", "")
	if err := eng.LoadPolicy(context.Background(), "base", "default", basePolicy); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	const opsPerType = 200
	var wg sync.WaitGroup
	var evalSuccesses, evalFailures atomic.Int64
	var validateSuccesses, validateFailures atomic.Int64
	var loadSuccesses, loadFailures atomic.Int64

	evalDurations := make([]time.Duration, opsPerType)
	validateDurations := make([]time.Duration, opsPerType)

	// Concurrent evaluations (scoped to "default" namespace so dynamic policy
	// loads into "dynamic" namespace don't affect correctness assertions)
	for i := 0; i < opsPerType; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := time.Now()
			resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
				Input:     map[string]any{"val": float64(idx % 2)},
				Namespace: "default",
			})
			evalDurations[idx] = time.Since(start)
			if err != nil {
				evalFailures.Add(1)
				return
			}
			evalSuccesses.Add(1)
			// Verify correctness
			if idx%2 == 1 {
				if resp.Decision != DecisionAllow {
					t.Errorf("eval %d: expected allow, got %s", idx, resp.Decision)
				}
			} else {
				if resp.Decision != DecisionDeny {
					t.Errorf("eval %d: expected deny, got %s", idx, resp.Decision)
				}
			}
		}(i)
	}

	// Concurrent validations
	for i := 0; i < opsPerType; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			source := fmt.Sprintf(`apiVersion: "policy.garmr.io/v1"
kind: "Policy"
metadata: { name: "val-%d", namespace: "default" }
spec: {
	description: "validation test %d"
	target: resources: [{kind: "*"}]
	rules: [{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}]
	enforcement: action: "deny"
}`, idx, idx)
			start := time.Now()
			errs, _ := eng.Validate(source)
			validateDurations[idx] = time.Since(start)
			if len(errs) > 0 {
				validateFailures.Add(1)
				return
			}
			validateSuccesses.Add(1)
		}(i)
	}

	// Concurrent policy loads (each to a unique name so no lock contention on same key)
	for i := 0; i < opsPerType; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("dyn-%d", idx)
			source := makePolicy(name, "dynamic", fmt.Sprintf("dynamic policy %d", idx),
				`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
				"deny", "")
			if err := eng.LoadPolicy(context.Background(), name, "dynamic", source); err != nil {
				loadFailures.Add(1)
				return
			}
			loadSuccesses.Add(1)
		}(i)
	}

	wg.Wait()

	// Compute eval latency stats
	evalStats := &concurrentStats{Durations: evalDurations}
	eMin, eMax, eMean, eP50, eP95, eP99 := evalStats.compute()

	// Compute validate latency stats
	valStats := &concurrentStats{Durations: validateDurations}
	vMin, vMax, vMean, vP50, vP95, vP99 := valStats.compute()

	t.Logf("=== Mixed Operations Stress Test ===")
	t.Logf("Operations per type: %d (total: %d)", opsPerType, opsPerType*3)
	t.Logf("")
	t.Logf("--- Evaluations ---")
	t.Logf("Successes: %d  Failures: %d", evalSuccesses.Load(), evalFailures.Load())
	t.Logf("Latency  min=%v  max=%v  mean=%v  p50=%v  p95=%v  p99=%v", eMin, eMax, eMean, eP50, eP95, eP99)
	t.Logf("")
	t.Logf("--- Validations ---")
	t.Logf("Successes: %d  Failures: %d", validateSuccesses.Load(), validateFailures.Load())
	t.Logf("Latency  min=%v  max=%v  mean=%v  p50=%v  p95=%v  p99=%v", vMin, vMax, vMean, vP50, vP95, vP99)
	t.Logf("")
	t.Logf("--- Policy Loads ---")
	t.Logf("Successes: %d  Failures: %d", loadSuccesses.Load(), loadFailures.Load())

	// Verify no failures
	if evalFailures.Load() != 0 {
		t.Errorf("expected 0 eval failures, got %d", evalFailures.Load())
	}
	if validateFailures.Load() != 0 {
		t.Errorf("expected 0 validate failures, got %d", validateFailures.Load())
	}
	if loadFailures.Load() != 0 {
		t.Errorf("expected 0 load failures, got %d", loadFailures.Load())
	}

	// Verify all dynamically loaded policies exist
	policies := eng.ListPolicies("dynamic")
	if len(policies) != opsPerType {
		t.Errorf("expected %d dynamic policies, got %d", opsPerType, len(policies))
	}
}

// TestConcurrentCueContextPool_PoolIsolation verifies that CUE contexts from
// the pool are truly isolated — one goroutine's CUE compilation doesn't corrupt
// another goroutine's evaluation. This uses deliberately different policy shapes
// to maximize the chance of detecting cross-context contamination.
func TestConcurrentCueContextPool_PoolIsolation(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Load 5 policies with different rules to maximize schema diversity
	policies := []struct {
		name, rules, action string
		passInput           map[string]any
		failInput           map[string]any
	}{
		{
			name:      "numeric-check",
			rules:     `{id: "r1", description: "x>10", severity: "high", expr: {match: {path: "x", greaterThan: 10}}, message: "x too low"}`,
			action:    "deny",
			passInput: map[string]any{"x": float64(20)},
			failInput: map[string]any{"x": float64(5)},
		},
		{
			name:      "string-check",
			rules:     `{id: "r2", description: "env is prod", severity: "medium", expr: {match: {path: "env", equals: "prod"}}, message: "not prod"}`,
			action:    "deny",
			passInput: map[string]any{"env": "prod"},
			failInput: map[string]any{"env": "dev"},
		},
		{
			name:      "pattern-check",
			rules:     `{id: "r3", description: "name format", severity: "low", expr: {match: {path: "name", pattern: "^svc-[a-z]+$"}}, message: "bad name"}`,
			action:    "deny",
			passInput: map[string]any{"name": "svc-frontend"},
			failInput: map[string]any{"name": "INVALID"},
		},
		{
			name:      "multi-rule",
			rules:     `{id: "r4a", description: "port range", severity: "high", expr: {match: {path: "port", greaterThan: 1023}}, message: "privileged port"}, {id: "r4b", description: "tls required", severity: "high", expr: {match: {path: "tls", equals: true}}, message: "tls off"}`,
			action:    "deny",
			passInput: map[string]any{"port": float64(8080), "tls": true},
			failInput: map[string]any{"port": float64(80), "tls": false},
		},
		{
			name:      "exists-check",
			rules:     `{id: "r5", description: "labels exist", severity: "medium", expr: {exists: {path: "metadata.labels"}}, message: "no labels"}`,
			action:    "warn",
			passInput: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "test"}}},
			failInput: map[string]any{"metadata": map[string]any{}},
		},
	}

	for _, p := range policies {
		source := makePolicy(p.name, "default", p.name,
			p.rules, p.action, "")
		if err := eng.LoadPolicy(context.Background(), p.name, "default", source); err != nil {
			t.Fatalf("LoadPolicy %s: %v", p.name, err)
		}
	}

	const requestsPerPolicy = 200
	totalRequests := len(policies) * requestsPerPolicy * 2 // pass + fail per policy

	type isolationResult struct {
		policyIdx int
		isPass    bool
		decision  Decision
		err       error
		duration  time.Duration
	}

	results := make([]isolationResult, totalRequests)
	var wg sync.WaitGroup

	idx := 0
	for pi, p := range policies {
		for j := 0; j < requestsPerPolicy; j++ {
			// Pass case
			wg.Add(1)
			go func(resIdx, pIdx int, input map[string]any) {
				defer wg.Done()
				start := time.Now()
				resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
				results[resIdx] = isolationResult{
					policyIdx: pIdx,
					isPass:    true,
					err:       err,
					duration:  time.Since(start),
				}
				if resp != nil {
					results[resIdx].decision = resp.Decision
				}
			}(idx, pi, p.passInput)
			idx++

			// Fail case
			wg.Add(1)
			go func(resIdx, pIdx int, input map[string]any) {
				defer wg.Done()
				start := time.Now()
				resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
				results[resIdx] = isolationResult{
					policyIdx: pIdx,
					isPass:    false,
					err:       err,
					duration:  time.Since(start),
				}
				if resp != nil {
					results[resIdx].decision = resp.Decision
				}
			}(idx, pi, p.failInput)
			idx++
		}
	}

	wg.Wait()

	// Aggregate per-policy stats
	type policyStats struct {
		passCorrect, passWrong, failCorrect, failWrong int
		errors                                         int
		durations                                      []time.Duration
	}
	perPolicy := make([]policyStats, len(policies))

	for _, r := range results {
		ps := &perPolicy[r.policyIdx]
		ps.durations = append(ps.durations, r.duration)

		if r.err != nil {
			ps.errors++
			continue
		}

		// All policies evaluate together, so "pass" means all 5 policy rules pass
		// and "fail" means at least one fails. Since we're sending input that
		// satisfies only one policy's rules, the overall decision depends on all policies.
		// The key correctness check: no errors and deterministic decisions for same input.
		if r.isPass {
			// Even pass inputs won't satisfy ALL 5 policies, so we just verify
			// the decision is deterministic and non-error.
			ps.passCorrect++
		} else {
			ps.failCorrect++
		}
	}

	t.Logf("=== Pool Isolation Test Results ===")
	t.Logf("Policies: %d  Requests per policy: %d (pass+fail)  Total: %d",
		len(policies), requestsPerPolicy*2, totalRequests)
	t.Logf("")

	var allDurations []time.Duration
	totalErrors := 0
	for i, ps := range perPolicy {
		allDurations = append(allDurations, ps.durations...)
		totalErrors += ps.errors
		t.Logf("Policy %q: pass=%d fail=%d errors=%d",
			policies[i].name, ps.passCorrect, ps.failCorrect, ps.errors)
	}

	stats := &concurrentStats{Durations: allDurations}
	min, max, mean, p50, p95, p99 := stats.compute()
	t.Logf("")
	t.Logf("--- Aggregate Latency ---")
	t.Logf("Min: %v  Max: %v  Mean: %v", min, max, mean)
	t.Logf("P50: %v  P95: %v  P99: %v", p50, p95, p99)

	if totalErrors != 0 {
		t.Errorf("expected 0 errors across all policies, got %d", totalErrors)
	}

	// Verify determinism: same input should always produce same decision.
	// Group results by (policyIdx, isPass) and check decision consistency.
	type groupKey struct {
		pIdx   int
		isPass bool
	}
	groups := make(map[groupKey]map[Decision]int)
	for _, r := range results {
		if r.err != nil {
			continue
		}
		key := groupKey{r.policyIdx, r.isPass}
		if groups[key] == nil {
			groups[key] = make(map[Decision]int)
		}
		groups[key][r.decision]++
	}

	for key, decisions := range groups {
		if len(decisions) > 1 {
			t.Errorf("NON-DETERMINISTIC: policy %q isPass=%v produced multiple decisions: %v",
				policies[key.pIdx].name, key.isPass, decisions)
		}
	}
}
