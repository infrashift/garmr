package engine

import (
	"context"
	"fmt"
	"testing"
)

// Engine-level benchmarks. They use only the public load/evaluate API so the
// same benchmarks measure the engine before and after internal rewrites.
//
//	go test ./internal/engine -run '^$' -bench 'BenchmarkEvaluate' -benchmem

const benchSimpleRules = `{
	id: "r1"
	description: "environment is production"
	severity: "high"
	expr: match: {path: "metadata.labels.env", equals: "prod"}
}, {
	id: "r2"
	description: "region is allowed"
	severity: "medium"
	expr: match: {path: "spec.region", in: ["us-east-1", "us-west-2", "eu-west-1"]}
}, {
	id: "r3"
	description: "image is pinned"
	severity: "low"
	expr: match: {path: "spec.image", pattern: "^registry\\.example\\.com/.+:[0-9]+\\.[0-9]+\\.[0-9]+$"}
}`

func benchSimpleInput() map[string]any {
	return map[string]any{
		"kind":       "Deployment",
		"apiVersion": "apps/v1",
		"metadata": map[string]any{
			"name":   "web",
			"labels": map[string]any{"env": "prod", "team": "payments"},
		},
		"spec": map[string]any{
			"region":   "us-east-1",
			"image":    "registry.example.com/web:1.2.3",
			"replicas": float64(3),
		},
	}
}

func newBenchEngine(b *testing.B, sources map[string]string) *Engine {
	b.Helper()
	eng, err := NewEngine(nil)
	if err != nil {
		b.Fatal(err)
	}
	for name, src := range sources {
		if err := eng.LoadPolicy(context.Background(), name, "default", src); err != nil {
			b.Fatal(err)
		}
	}
	return eng
}

func BenchmarkEvaluate_Simple(b *testing.B) {
	eng := newBenchEngine(b, map[string]string{
		"simple": makePolicy("simple", "default", "bench", benchSimpleRules, "deny", ""),
	})
	req := &EvaluateRequest{Input: benchSimpleInput()}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := eng.Evaluate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		if resp.Decision != DecisionAllow {
			b.Fatalf("decision = %s, want allow: %+v", resp.Decision, resp.Results)
		}
	}
}

// BenchmarkEvaluate_SimpleParallel shows how evaluation throughput scales with
// cores. Evaluations read an immutable snapshot without locks, so it should
// scale with GOMAXPROCS rather than flatten.
func BenchmarkEvaluate_SimpleParallel(b *testing.B) {
	eng := newBenchEngine(b, map[string]string{
		"simple": makePolicy("simple", "default", "bench", benchSimpleRules, "deny", ""),
	})
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := &EvaluateRequest{Input: benchSimpleInput()}
		for pb.Next() {
			if _, err := eng.Evaluate(ctx, req); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkEvaluate_ManyPolicies loads 500 policies that each target a
// distinct kind; the input matches exactly one. It measures the cost of
// finding applicable policies in a large set.
func BenchmarkEvaluate_ManyPolicies(b *testing.B) {
	const n = 500
	sources := make(map[string]string, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("p%d", i)
		src := fmt.Sprintf(`
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: %q, namespace: "default"}
spec: {
	target: resources: [{kind: "Kind%d"}]
	rules: [%s]
	enforcement: action: "deny"
}`, name, i, benchSimpleRules)
		sources[name] = src
	}
	eng := newBenchEngine(b, sources)

	input := benchSimpleInput()
	input["kind"] = "Kind250"
	req := &EvaluateRequest{Input: input}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := eng.Evaluate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		if resp.Metrics.PoliciesEvaluated != 1 {
			b.Fatalf("policies evaluated = %d, want 1", resp.Metrics.PoliciesEvaluated)
		}
	}
}
