// Package benchopa benchmarks OPA on the same scenarios as Garmr's engine
// benchmarks (internal/engine/bench_test.go), for a like-for-like
// comparison. It is a separate module so OPA never becomes a Garmr
// dependency.
//
//	cd scripts/bench-opa && go test -run '^$' -bench . -benchmem
//	cd ../.. && go test ./internal/engine -run '^$' -bench 'BenchmarkEvaluate|BenchmarkForEach' -benchmem
//
// Both sides evaluate a Go map input through their in-process API with the
// policy compiled once up front (OPA: rego.PreparedEvalQuery; Garmr:
// Engine.Evaluate on a loaded set).
package benchopa

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

// simpleRules mirrors benchSimpleRules: three checks on a Deployment.
const simpleRules = `
deny contains "env" if input.metadata.labels.env != "prod"

deny contains "region" if not input.spec.region in {"us-east-1", "us-west-2", "eu-west-1"}

deny contains "image" if not regex.match(` + "`" + `^registry\.example\.com/.+:[0-9]+\.[0-9]+\.[0-9]+$` + "`" + `, input.spec.image)
`

func simpleInput() map[string]any {
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

func prepare(b *testing.B, module string) rego.PreparedEvalQuery {
	b.Helper()
	pq, err := rego.New(
		rego.Query("data.bench.deny"),
		rego.Module("bench.rego", "package bench\n\n"+module),
	).PrepareForEval(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	return pq
}

func eval(b *testing.B, pq rego.PreparedEvalQuery, input map[string]any, wantDenies int) {
	rs, err := pq.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		b.Fatal(err)
	}
	got := 0
	if len(rs) > 0 {
		got = len(rs[0].Expressions[0].Value.([]any))
	}
	if got != wantDenies {
		b.Fatalf("denies = %d, want %d", got, wantDenies)
	}
}

func BenchmarkOPA_Simple(b *testing.B) {
	pq := prepare(b, simpleRules)
	input := simpleInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval(b, pq, input, 0)
	}
}

func BenchmarkOPA_SimpleParallel(b *testing.B) {
	pq := prepare(b, simpleRules)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		input := simpleInput()
		for pb.Next() {
			eval(b, pq, input, 0)
		}
	})
}

// BenchmarkOPA_ManyPolicies mirrors BenchmarkEvaluate_ManyPolicies: 500 rule
// groups, each guarded by a distinct kind, and an input matching one.
func BenchmarkOPA_ManyPolicies(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, `
deny contains "env-%[1]d" if { input.kind == "Kind%[1]d"; input.metadata.labels.env != "prod" }
deny contains "region-%[1]d" if { input.kind == "Kind%[1]d"; not input.spec.region in {"us-east-1", "us-west-2", "eu-west-1"} }
deny contains "image-%[1]d" if { input.kind == "Kind%[1]d"; not regex.match(`+"`"+`^registry\.example\.com/.+:[0-9]+\.[0-9]+\.[0-9]+$`+"`"+`, input.spec.image) }
`, i)
	}
	pq := prepare(b, sb.String())
	input := simpleInput()
	input["kind"] = "Kind250"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval(b, pq, input, 0)
	}
}

// BenchmarkOPA_ForEach_LargeInput mirrors BenchmarkForEach_LargeInput: 50
// iterated elements alongside 200 padding objects.
func BenchmarkOPA_ForEach_LargeInput(b *testing.B) {
	pq := prepare(b, `deny contains "entry" if { some e in input.entries; e.enabled != true }`)
	padding := make(map[string]any, 200)
	for i := 0; i < 200; i++ {
		padding[fmt.Sprintf("key%d", i)] = map[string]any{"a": i, "b": "some padding value"}
	}
	entries := make([]any, 50)
	for i := range entries {
		entries[i] = map[string]any{"enabled": true}
	}
	input := map[string]any{"kind": "Big", "padding": padding, "entries": entries}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval(b, pq, input, 0)
	}
}
