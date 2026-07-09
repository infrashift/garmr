package engine

import (
	"context"
	"fmt"
	"testing"
)

// --- Expression Evaluation: Match Operators ---

func TestEvaluate_MatchEquals(t *testing.T) {
	source := makePolicy("eq-test", "default", "equals test",
		`{id: "r1", description: "check env", severity: "high", expr: {match: {path: "env", equals: "prod"}}, message: "env must be prod"}`,
		"deny", "")
	eng := loadTestPolicy(t, "eq-test", "default", source)

	// Pass
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input:   map[string]any{"env": "prod"},
		Options: EvaluateOptions{IncludePassed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	// Fail
	resp, err = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchEquals_Numeric(t *testing.T) {
	source := makePolicy("num-eq", "default", "numeric equals",
		`{id: "r1", description: "check count", severity: "high", expr: {match: {path: "count", equals: 5}}, message: "count must be 5"}`,
		"deny", "")
	eng := loadTestPolicy(t, "num-eq", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"count": 5.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for count=5, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchGreaterThan(t *testing.T) {
	source := makePolicy("gt-test", "default", "gt test",
		`{id: "r1", description: "check replicas", severity: "medium", expr: {match: {path: "replicas", greaterThan: 0}}, message: "replicas must be > 0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "gt-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 3.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for replicas=3, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 0.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for replicas=0, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLessThan(t *testing.T) {
	source := makePolicy("lt-test", "default", "lt test",
		`{id: "r1", description: "check max", severity: "low", expr: {match: {path: "value", lessThan: 100}}, message: "value must be < 100"}`,
		"deny", "")
	eng := loadTestPolicy(t, "lt-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"value": 50.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for value=50, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"value": 100.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for value=100, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchIn(t *testing.T) {
	source := makePolicy("in-test", "default", "in test",
		`{id: "r1", description: "check env", severity: "high", expr: {match: {path: "env", in: ["prod", "staging"]}}, message: "env must be prod or staging"}`,
		"deny", "")
	eng := loadTestPolicy(t, "in-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for env=prod, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for env=dev, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchNotIn(t *testing.T) {
	source := makePolicy("notin-test", "default", "notIn test",
		`{id: "r1", description: "block envs", severity: "high", expr: {match: {path: "env", notIn: ["dev", "test"]}}, message: "env forbidden"}`,
		"deny", "")
	eng := loadTestPolicy(t, "notin-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for env=prod, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for env=dev, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchContains(t *testing.T) {
	source := makePolicy("contains-test", "default", "contains test",
		`{id: "r1", description: "check name", severity: "low", expr: {match: {path: "name", contains: "app"}}, message: "name must contain app"}`,
		"deny", "")
	eng := loadTestPolicy(t, "contains-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"name": "my-app-service"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchPattern(t *testing.T) {
	source := makePolicy("pattern-test", "default", "pattern test",
		`{id: "r1", description: "check version", severity: "medium", expr: {match: {path: "version", pattern: "^v\\d+\\.\\d+\\.\\d+$"}}, message: "version must match semver"}`,
		"deny", "")
	eng := loadTestPolicy(t, "pattern-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "v1.2.3"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "latest"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Exists / Absent ---

func TestEvaluate_Exists(t *testing.T) {
	source := makePolicy("exists-test", "default", "exists test",
		`{id: "r1", description: "check labels", severity: "high", expr: {exists: "metadata.labels"}, message: "labels required"}`,
		"deny", "")
	eng := loadTestPolicy(t, "exists-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "test"}}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"metadata": map[string]any{}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Absent(t *testing.T) {
	source := makePolicy("absent-test", "default", "absent test",
		`{id: "r1", description: "check hostNetwork", severity: "critical", expr: {absent: "spec.hostNetwork"}, message: "hostNetwork must not be set"}`,
		"deny", "")
	eng := loadTestPolicy(t, "absent-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{"hostNetwork": true}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Logical Combinators ---

func TestEvaluate_All(t *testing.T) {
	source := makePolicy("all-test", "default", "all test",
		`{id: "r1", description: "all conditions", severity: "high", expr: {all: [
			{match: {path: "a", equals: 1}},
			{match: {path: "b", equals: 2}}
		]}, message: "all must match"}`,
		"deny", "")
	eng := loadTestPolicy(t, "all-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"a": 1.0, "b": 2.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"a": 1.0, "b": 3.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Any(t *testing.T) {
	source := makePolicy("any-test", "default", "any test",
		`{id: "r1", description: "any condition", severity: "high", expr: {any: [
			{match: {path: "env", equals: "prod"}},
			{match: {path: "env", equals: "staging"}}
		]}, message: "env must be prod or staging"}`,
		"deny", "")
	eng := loadTestPolicy(t, "any-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "staging"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Not(t *testing.T) {
	source := makePolicy("not-test", "default", "not test",
		`{id: "r1", description: "not dev", severity: "high", expr: {not: {match: {path: "env", equals: "dev"}}}, message: "must not be dev"}`,
		"deny", "")
	eng := loadTestPolicy(t, "not-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- ForEach ---

func TestEvaluate_ForEach(t *testing.T) {
	source := makePolicy("foreach-test", "default", "forEach test",
		`{
			id: "r1"
			description: "all containers must have image"
			severity: "high"
			expr: {forEach: {
				path: "spec.containers"
				as: "container"
				condition: {exists: "container.image"}
			}}
			message: "all containers need image"
		}`,
		"deny", "")
	eng := loadTestPolicy(t, "foreach-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{"name": "app", "image": "nginx"},
					map[string]any{"name": "sidecar", "image": "envoy"},
				},
			},
		},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}

// TestEvaluate_ForEach_AliasCollision covers inputs that already carry a
// top-level field with the same name as the forEach alias: the element
// binding must shadow the input's own field (the FillPath fast path cannot
// do this, so this exercises the rebuild fallback).
func TestEvaluate_ForEach_AliasCollision(t *testing.T) {
	source := makePolicy("foreach-collision", "default", "alias collision",
		`{
			id: "r1"
			description: "all entries must be enabled"
			severity: "high"
			expr: {forEach: {
				path: "entries"
				as: "item"
				condition: {match: {path: "item.enabled", equals: true}}
			}}
			message: "all entries must be enabled"
		}`,
		"deny", "")
	eng := loadTestPolicy(t, "foreach-collision", "default", source)

	// The input's own "item" field would fail the condition; the bound
	// array elements pass. If the alias didn't shadow it, this would deny.
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{
			"kind": "Config",
			"item": map[string]any{"enabled": false},
			"entries": []any{
				map[string]any{"enabled": true},
				map[string]any{"enabled": true},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected alias to shadow input field (allow), got %s", resp.Decision)
	}
}

// TestEvaluate_ForEach_Nested exercises a forEach inside a forEach: the
// inner iteration re-binds "_index", which forces the rebuild fallback and
// must not corrupt the outer binding.
func TestEvaluate_ForEach_Nested(t *testing.T) {
	source := makePolicy("foreach-nested", "default", "nested forEach",
		`{
			id: "r1"
			description: "every container port must be above 1024"
			severity: "high"
			expr: {forEach: {
				path: "spec.containers"
				as: "container"
				condition: {forEach: {
					path: "container.ports"
					as: "port"
					condition: {match: {path: "port.number", greaterThan: 1024}}
				}}
			}}
			message: "privileged ports are not allowed"
		}`,
		"deny", "")
	eng := loadTestPolicy(t, "foreach-nested", "default", source)

	makeInput := func(sidecarPort int) map[string]any {
		return map[string]any{
			"kind": "Pod",
			"spec": map[string]any{
				"containers": []any{
					map[string]any{"name": "app", "ports": []any{
						map[string]any{"number": 8080},
						map[string]any{"number": 9090},
					}},
					map[string]any{"name": "sidecar", "ports": []any{
						map[string]any{"number": sidecarPort},
					}},
				},
			},
		}
	}

	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: makeInput(15021)})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for unprivileged ports, got %s", resp.Decision)
	}

	resp, err = eng.Evaluate(context.Background(), &EvaluateRequest{Input: makeInput(80)})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for privileged port, got %s", resp.Decision)
	}
}

// BenchmarkForEach_LargeInput measures forEach cost on a large input. The
// "fastpath" case grafts elements via FillPath; the "fallback" case forces
// the decode/re-encode rebuild (the pre-optimization behavior) via an alias
// collision, so the two cases directly compare the old and new paths.
func BenchmarkForEach_LargeInput(b *testing.B) {
	source := makePolicy("foreach-bench", "default", "bench",
		`{
			id: "r1"
			description: "all entries enabled"
			severity: "low"
			expr: {forEach: {
				path: "entries"
				as: "entry"
				condition: {match: {path: "entry.enabled", equals: true}}
			}}
		}`,
		"deny", "")

	eng, err := NewEngine(nil)
	if err != nil {
		b.Fatal(err)
	}
	if err := eng.LoadPolicy(context.Background(), "foreach-bench", "default", source); err != nil {
		b.Fatal(err)
	}

	// Large input: 200 padding objects plus 50 iterated elements.
	makeInput := func(collide bool) map[string]any {
		padding := make(map[string]any, 200)
		for i := 0; i < 200; i++ {
			padding[fmt.Sprintf("key%d", i)] = map[string]any{"a": i, "b": "some padding value"}
		}
		entries := make([]any, 50)
		for i := range entries {
			entries[i] = map[string]any{"enabled": true}
		}
		input := map[string]any{"kind": "Big", "padding": padding, "entries": entries}
		if collide {
			input["entry"] = "collides with alias"
		}
		return input
	}

	for name, collide := range map[string]bool{"fastpath": false, "fallback": true} {
		b.Run(name, func(b *testing.B) {
			input := makeInput(collide)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// --- Contains Expression ---

func TestEvaluate_ContainsExpr(t *testing.T) {
	source := makePolicy("contains-expr", "default", "contains expr test",
		`{id: "r1", description: "check tags", severity: "medium", expr: {contains: {path: "tags", value: "production"}}, message: "must have production tag"}`,
		"deny", "")
	eng := loadTestPolicy(t, "contains-expr", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tags": []any{"production", "reviewed"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tags": []any{"staging"}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Compare Expression ---

func TestEvaluate_Compare(t *testing.T) {
	source := makePolicy("compare-test", "default", "compare test",
		`{id: "r1", description: "compare values", severity: "high", expr: {compare: {
			left: {path: "replicas"}
			op: ">="
			right: {literal: 2}
		}}, message: "replicas must be >= 2"}`,
		"deny", "")
	eng := loadTestPolicy(t, "compare-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 3.0},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": 1.0},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Func Expression ---

func TestEvaluate_Func(t *testing.T) {
	source := makePolicy("func-test", "default", "func test",
		`{id: "r1", description: "check length", severity: "medium", expr: {func: {
			name: "len"
			args: ["input.items"]
			expect: 3
		}}, message: "must have exactly 3 items"}`,
		"deny", "")
	eng := loadTestPolicy(t, "func-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b", "c"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b"}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- Multifield match exists within match ---

func TestEvaluate_MatchExists(t *testing.T) {
	source := makePolicy("matchexists-test", "default", "match exists test",
		`{id: "r1", description: "field must exist", severity: "high", expr: {match: {path: "spec.replicas", exists: true}}, message: "replicas required"}`,
		"deny", "")
	eng := loadTestPolicy(t, "matchexists-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{"replicas": 3.0}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"spec": map[string]any{}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

// --- GreaterThanOrEqual / LessThanOrEqual ---

func TestEvaluate_MatchGTE(t *testing.T) {
	source := makePolicy("gte-test", "default", "gte test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "v", greaterThanOrEqual: 10}}, message: "must be >= 10"}`,
		"deny", "")
	eng := loadTestPolicy(t, "gte-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 10.0}})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for v=10, got %s", resp.Decision)
	}
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 9.0}})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for v=9, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLTE(t *testing.T) {
	source := makePolicy("lte-test", "default", "lte test",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "v", lessThanOrEqual: 100}}, message: "must be <= 100"}`,
		"deny", "")
	eng := loadTestPolicy(t, "lte-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 100.0}})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for v=100, got %s", resp.Decision)
	}
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{"v": 101.0}})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for v=101, got %s", resp.Decision)
	}
}

// --- Match: hasPrefix ---

func TestEvaluate_MatchHasPrefix(t *testing.T) {
	source := makePolicy("prefix-test", "default", "hasPrefix test",
		`{id: "r1", description: "check image registry", severity: "high", expr: {match: {path: "image", hasPrefix: "gcr.io/"}}, message: "image must be from gcr.io"}`,
		"deny", "")
	eng := loadTestPolicy(t, "prefix-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"image": "gcr.io/my-project/app:v1"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for gcr.io prefix, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"image": "docker.io/nginx:latest"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for docker.io prefix, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchHasPrefix_EmptyString(t *testing.T) {
	source := makePolicy("prefix-empty", "default", "hasPrefix empty",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "name", hasPrefix: "app-"}}, message: "must start with app-"}`,
		"deny", "")
	eng := loadTestPolicy(t, "prefix-empty", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"name": ""},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for empty string, got %s", resp.Decision)
	}
}

// --- Match: hasSuffix ---

func TestEvaluate_MatchHasSuffix(t *testing.T) {
	source := makePolicy("suffix-test", "default", "hasSuffix test",
		`{id: "r1", description: "check domain", severity: "medium", expr: {match: {path: "domain", hasSuffix: ".example.com"}}, message: "domain must end with .example.com"}`,
		"deny", "")
	eng := loadTestPolicy(t, "suffix-test", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"domain": "api.example.com"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for .example.com suffix, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"domain": "api.other.com"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for .other.com suffix, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchHasSuffix_ExactMatch(t *testing.T) {
	source := makePolicy("suffix-exact", "default", "hasSuffix exact",
		`{id: "r1", description: "check ext", severity: "low", expr: {match: {path: "file", hasSuffix: ".yaml"}}, message: "must be yaml"}`,
		"deny", "")
	eng := loadTestPolicy(t, "suffix-exact", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"file": ".yaml"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for exact suffix match, got %s", resp.Decision)
	}
}

// --- Match: length ---

func TestEvaluate_MatchLength_Equals(t *testing.T) {
	source := makePolicy("len-eq", "default", "length equals",
		`{id: "r1", description: "check items", severity: "medium", expr: {match: {path: "items", length: {equals: 3}}}, message: "must have exactly 3 items"}`,
		"deny", "")
	eng := loadTestPolicy(t, "len-eq", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b", "c"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for length=3, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b"}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for length=2, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLength_GreaterThan(t *testing.T) {
	source := makePolicy("len-gt", "default", "length gt",
		`{id: "r1", description: "check tags", severity: "low", expr: {match: {path: "tags", length: {greaterThan: 0}}}, message: "must have at least one tag"}`,
		"deny", "")
	eng := loadTestPolicy(t, "len-gt", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tags": []any{"prod"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for length=1 > 0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tags": []any{}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for empty array, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLength_LessThanOrEqual(t *testing.T) {
	source := makePolicy("len-lte", "default", "length lte",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "items", length: {lessThanOrEqual: 5}}}, message: "max 5 items"}`,
		"deny", "")
	eng := loadTestPolicy(t, "len-lte", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b", "c", "d", "e"}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for length=5, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"items": []any{"a", "b", "c", "d", "e", "f"}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for length=6, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLength_MinMax(t *testing.T) {
	source := makePolicy("len-minmax", "default", "length min/max",
		`{id: "r1", description: "check", severity: "medium", expr: {match: {path: "replicas", length: {min: 2, max: 5}}}, message: "replicas must be 2-5"}`,
		"deny", "")
	eng := loadTestPolicy(t, "len-minmax", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": []any{1, 2, 3}},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for length=3 in [2,5], got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": []any{1}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for length=1 < min=2, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"replicas": []any{1, 2, 3, 4, 5, 6}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for length=6 > max=5, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchLength_StringLength(t *testing.T) {
	source := makePolicy("len-str", "default", "string length",
		`{id: "r1", description: "check password", severity: "high", expr: {match: {path: "password", length: {greaterThanOrEqual: 8}}}, message: "password must be at least 8 chars"}`,
		"deny", "")
	eng := loadTestPolicy(t, "len-str", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"password": "securepassword"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 14-char string, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"password": "short"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 5-char string, got %s", resp.Decision)
	}
}

// --- Match: semver ---

func TestEvaluate_MatchSemver_Equals(t *testing.T) {
	source := makePolicy("sv-eq", "default", "semver equals",
		`{id: "r1", description: "check version", severity: "high", expr: {match: {path: "version", semver: {equals: "2.0.0"}}}, message: "version must be 2.0.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "sv-eq", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.0.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 2.0.0 == 2.0.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "1.9.0"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 1.9.0 != 2.0.0, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchSemver_GreaterThanOrEqual(t *testing.T) {
	source := makePolicy("sv-gte", "default", "semver gte",
		`{id: "r1", description: "min version", severity: "high", expr: {match: {path: "version", semver: {greaterThanOrEqual: "1.5.0"}}}, message: "version must be >= 1.5.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "sv-gte", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "1.5.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 1.5.0 >= 1.5.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.0.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 2.0.0 >= 1.5.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "1.4.9"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 1.4.9 < 1.5.0, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchSemver_LessThan(t *testing.T) {
	source := makePolicy("sv-lt", "default", "semver lt",
		`{id: "r1", description: "max version", severity: "medium", expr: {match: {path: "version", semver: {lessThan: "3.0.0"}}}, message: "version must be < 3.0.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "sv-lt", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.9.9"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 2.9.9 < 3.0.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "3.0.0"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 3.0.0 not < 3.0.0, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchSemver_Constraint(t *testing.T) {
	source := makePolicy("sv-constraint", "default", "semver constraint",
		`{id: "r1", description: "version range", severity: "high", expr: {match: {path: "version", semver: {constraint: ">=1.0.0,<2.0.0"}}}, message: "version must be ^1.x"}`,
		"deny", "")
	eng := loadTestPolicy(t, "sv-constraint", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "1.5.3"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 1.5.3 in [1.0.0, 2.0.0), got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.0.0"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 2.0.0 not in [1.0.0, 2.0.0), got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "0.9.9"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 0.9.9 not in [1.0.0, 2.0.0), got %s", resp.Decision)
	}
}

func TestEvaluate_MatchSemver_VPrefix(t *testing.T) {
	source := makePolicy("sv-vprefix", "default", "semver v-prefix",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "version", semver: {greaterThan: "1.0.0"}}}, message: "must be > 1.0.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "sv-vprefix", "default", source)

	// v-prefix should be handled
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "v2.0.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for v2.0.0 > 1.0.0, got %s", resp.Decision)
	}
}

// --- Match: datetime ---

func TestEvaluate_MatchDatetime_After(t *testing.T) {
	source := makePolicy("dt-after", "default", "datetime after",
		`{id: "r1", description: "check date", severity: "high", expr: {match: {path: "created_at", datetime: {after: "2024-01-01T00:00:00Z"}}}, message: "must be after 2024-01-01"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-after", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"created_at": "2024-06-15T12:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for date after 2024-01-01, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"created_at": "2023-12-31T23:59:59Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date before 2024-01-01, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchDatetime_Before(t *testing.T) {
	source := makePolicy("dt-before", "default", "datetime before",
		`{id: "r1", description: "check expiry", severity: "high", expr: {match: {path: "expires_at", datetime: {before: "2030-01-01T00:00:00Z"}}}, message: "must expire before 2030"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-before", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"expires_at": "2029-12-31T23:59:59Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for date before 2030, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"expires_at": "2030-01-01T00:00:01Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date after 2030, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchDatetime_AfterOrEqual(t *testing.T) {
	source := makePolicy("dt-aftereq", "default", "datetime afterOrEqual",
		`{id: "r1", description: "check", severity: "medium", expr: {match: {path: "start_date", datetime: {afterOrEqual: "2024-06-01T00:00:00Z"}}}, message: "must be on or after 2024-06-01"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-aftereq", "default", source)

	// Exact match should pass
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"start_date": "2024-06-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for exact match, got %s", resp.Decision)
	}

	// After should pass
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"start_date": "2024-07-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for date after, got %s", resp.Decision)
	}

	// Before should fail
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"start_date": "2024-05-31T23:59:59Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date before, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchDatetime_BeforeOrEqual(t *testing.T) {
	source := makePolicy("dt-beforeeq", "default", "datetime beforeOrEqual",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "end_date", datetime: {beforeOrEqual: "2025-12-31T23:59:59Z"}}}, message: "must be on or before end of 2025"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-beforeeq", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"end_date": "2025-12-31T23:59:59Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for exact match, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"end_date": "2026-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date after boundary, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchDatetime_NotExpired(t *testing.T) {
	source := makePolicy("dt-notexpired", "default", "datetime notExpired",
		`{id: "r1", description: "check cert", severity: "critical", expr: {match: {path: "cert_expiry", datetime: {notExpired: true}}}, message: "certificate has expired"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-notexpired", "default", source)

	// Future date should pass
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"cert_expiry": "2099-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for future cert, got %s", resp.Decision)
	}

	// Past date should fail
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"cert_expiry": "2020-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for expired cert, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchDatetime_ExpiresAfterDays(t *testing.T) {
	source := makePolicy("dt-expiresafter", "default", "datetime expiresAfterDays",
		`{id: "r1", description: "check cert", severity: "high", expr: {match: {path: "cert_expiry", datetime: {expiresAfterDays: 30}}}, message: "cert expires in less than 30 days"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-expiresafter", "default", source)

	// Far future should pass
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"cert_expiry": "2099-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for far-future expiry, got %s", resp.Decision)
	}

	// Already expired should fail
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"cert_expiry": "2020-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for already-expired cert, got %s", resp.Decision)
	}
}

func TestEvaluate_MatchDatetime_WithinDays(t *testing.T) {
	source := makePolicy("dt-withindays", "default", "datetime withinDays",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "deploy_date", datetime: {withinDays: 365}}}, message: "deploy date must be within 365 days"}`,
		"deny", "")
	eng := loadTestPolicy(t, "dt-withindays", "default", source)

	// Today should pass
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"deploy_date": "2020-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for past date within window, got %s", resp.Decision)
	}

	// Far future should fail
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"deploy_date": "2099-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for far-future date, got %s", resp.Decision)
	}
}

// --- Compare expression: semver operators ---

func TestEvaluate_Compare_SemverGt(t *testing.T) {
	source := makePolicy("cmp-svgt", "default", "compare semverGt",
		`{id: "r1", description: "version check", severity: "high", expr: {compare: {
			left: {path: "version"}
			op: "semverGt"
			right: {literal: "1.0.0"}
		}}, message: "version must be > 1.0.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-svgt", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.0.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 2.0.0 semverGt 1.0.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "1.0.0"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 1.0.0 not semverGt 1.0.0, got %s", resp.Decision)
	}
}

func TestEvaluate_Compare_SemverLte(t *testing.T) {
	source := makePolicy("cmp-svlte", "default", "compare semverLte",
		`{id: "r1", description: "max version", severity: "medium", expr: {compare: {
			left: {path: "version"}
			op: "semverLte"
			right: {literal: "3.0.0"}
		}}, message: "version must be <= 3.0.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-svlte", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "3.0.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 3.0.0 semverLte 3.0.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "3.0.1"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 3.0.1 not semverLte 3.0.0, got %s", resp.Decision)
	}
}

func TestEvaluate_Compare_SemverEq(t *testing.T) {
	source := makePolicy("cmp-sveq", "default", "compare semverEq",
		`{id: "r1", description: "exact version", severity: "low", expr: {compare: {
			left: {path: "version"}
			op: "semverEq"
			right: {literal: "2.1.0"}
		}}, message: "version must be exactly 2.1.0"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-sveq", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.1.0"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for 2.1.0 semverEq 2.1.0, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"version": "2.1.1"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for 2.1.1 != 2.1.0, got %s", resp.Decision)
	}
}

// --- Compare expression: datetime operators ---

func TestEvaluate_Compare_After(t *testing.T) {
	source := makePolicy("cmp-after", "default", "compare after",
		`{id: "r1", description: "date check", severity: "medium", expr: {compare: {
			left: {path: "deploy_date"}
			op: "after"
			right: {literal: "2024-01-01T00:00:00Z"}
		}}, message: "must be deployed after 2024-01-01"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-after", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"deploy_date": "2024-06-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for date after 2024-01-01, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"deploy_date": "2023-12-31T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date before 2024-01-01, got %s", resp.Decision)
	}
}

func TestEvaluate_Compare_Before(t *testing.T) {
	source := makePolicy("cmp-before", "default", "compare before",
		`{id: "r1", description: "deadline check", severity: "high", expr: {compare: {
			left: {path: "deadline"}
			op: "before"
			right: {literal: "2025-12-31T23:59:59Z"}
		}}, message: "deadline must be before end of 2025"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-before", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"deadline": "2025-06-01T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for date before 2025-12-31, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"deadline": "2026-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date after 2025-12-31, got %s", resp.Decision)
	}
}

func TestEvaluate_Compare_BeforeOrEqual(t *testing.T) {
	source := makePolicy("cmp-beforeeq", "default", "compare beforeOrEqual",
		`{id: "r1", description: "check", severity: "low", expr: {compare: {
			left: {path: "ts"}
			op: "beforeOrEqual"
			right: {literal: "2024-12-31T00:00:00Z"}
		}}, message: "ts must be <= 2024-12-31"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-beforeeq", "default", source)

	// Exact match should pass
	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"ts": "2024-12-31T00:00:00Z"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for exact match, got %s", resp.Decision)
	}

	// After should fail
	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"ts": "2025-01-01T00:00:00Z"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for date after, got %s", resp.Decision)
	}
}

// --- Compare expression: additional string operators ---

func TestEvaluate_Compare_Contains(t *testing.T) {
	source := makePolicy("cmp-contains", "default", "compare contains",
		`{id: "r1", description: "check", severity: "low", expr: {compare: {
			left: {path: "name"}
			op: "contains"
			right: {literal: "app"}
		}}, message: "name must contain app"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-contains", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"name": "my-app-service"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"name": "my-service"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluate_Compare_Matches(t *testing.T) {
	source := makePolicy("cmp-matches", "default", "compare matches",
		`{id: "r1", description: "check", severity: "low", expr: {compare: {
			left: {path: "tag"}
			op: "matches"
			right: {literal: "^v\\d+\\.\\d+$"}
		}}, message: "tag must match vX.Y"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-matches", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tag": "v1.2"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for v1.2, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"tag": "latest"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for latest, got %s", resp.Decision)
	}
}

func TestEvaluate_Compare_NotEqual(t *testing.T) {
	source := makePolicy("cmp-ne", "default", "compare ne",
		`{id: "r1", description: "check", severity: "low", expr: {compare: {
			left: {path: "env"}
			op: "!="
			right: {literal: "dev"}
		}}, message: "env must not be dev"}`,
		"deny", "")
	eng := loadTestPolicy(t, "cmp-ne", "default", source)

	resp, _ := eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow for prod != dev, got %s", resp.Decision)
	}

	resp, _ = eng.Evaluate(context.Background(), &EvaluateRequest{
		Input: map[string]any{"env": "dev"},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for dev == dev, got %s", resp.Decision)
	}
}

// --- compareDatetime ---

func TestCompareDatetime(t *testing.T) {
	r, err := compareDatetime("2024-01-15T12:00:00Z", "2024-01-14T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r <= 0 {
		t.Error("expected 2024-01-15 to be after 2024-01-14")
	}

	if _, err := compareDatetime("not-a-date", "2024-01-14T12:00:00Z"); err == nil {
		t.Error("expected error for unparseable datetime")
	}
}
