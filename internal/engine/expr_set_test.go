package engine

import (
	"context"
	"strings"
	"testing"
)

// setOpPolicy builds a single-rule deny policy with the given match block.
func setOpPolicy(t *testing.T, name, matchBlock string) *Engine {
	t.Helper()
	source := makePolicy(name, "default", "set op",
		`{id: "r1", description: "set check", severity: "high", expr: {match: {`+matchBlock+`}}}`,
		"deny", "")
	return loadTestPolicy(t, name, "default", source)
}

func evalSetOp(t *testing.T, eng *Engine, input map[string]any) *EvaluateResponse {
	t.Helper()
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	return resp
}

func TestMatchUnique(t *testing.T) {
	eng := setOpPolicy(t, "unique-pol", `path: "spec.ports", unique: true`)

	cases := []struct {
		name  string
		ports []any
		want  Decision
	}{
		{"distinct values", []any{80, 443, 8080}, DecisionAllow},
		{"duplicate values", []any{80, 443, 80}, DecisionDeny},
		{"numeric-aware duplicate", []any{80, 80.0}, DecisionDeny},
		{"empty array", []any{}, DecisionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evalSetOp(t, eng, map[string]any{
				"kind": "Service",
				"spec": map[string]any{"ports": tc.ports},
			})
			if resp.Decision != tc.want {
				t.Errorf("ports %v: expected %s, got %s", tc.ports, tc.want, resp.Decision)
			}
		})
	}

	t.Run("not an array", func(t *testing.T) {
		resp := evalSetOp(t, eng, map[string]any{
			"kind": "Service",
			"spec": map[string]any{"ports": "80"},
		})
		if resp.Decision != DecisionDeny {
			t.Errorf("expected deny for non-array, got %s", resp.Decision)
		}
		if !strings.Contains(resp.Results[0].Message, "not an array") {
			t.Errorf("expected not-an-array diagnostic, got %q", resp.Results[0].Message)
		}
	})

	t.Run("unique false is no constraint", func(t *testing.T) {
		lax := setOpPolicy(t, "unique-false", `path: "spec.ports", unique: false`)
		resp := evalSetOp(t, lax, map[string]any{
			"kind": "Service",
			"spec": map[string]any{"ports": []any{80, 80}},
		})
		if resp.Decision != DecisionAllow {
			t.Errorf("unique:false should not constrain, got %s", resp.Decision)
		}
	})
}

func TestMatchUniqueBy(t *testing.T) {
	eng := setOpPolicy(t, "uniqueby-pol", `path: "spec.containers", uniqueBy: "name"`)

	cases := []struct {
		name       string
		containers []any
		want       Decision
		wantMsg    string
	}{
		{
			"distinct names",
			[]any{map[string]any{"name": "app"}, map[string]any{"name": "sidecar"}},
			DecisionAllow, "",
		},
		{
			"duplicate names",
			[]any{map[string]any{"name": "app"}, map[string]any{"name": "app"}},
			DecisionDeny, "duplicate",
		},
		{
			"missing key field",
			[]any{map[string]any{"name": "app"}, map[string]any{"image": "nginx"}},
			DecisionDeny, "has no field 'name'",
		},
		{"empty array", []any{}, DecisionAllow, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evalSetOp(t, eng, map[string]any{
				"kind": "Pod",
				"spec": map[string]any{"containers": tc.containers},
			})
			if resp.Decision != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, resp.Decision)
			}
			if tc.wantMsg != "" && !strings.Contains(resp.Results[0].Message, tc.wantMsg) {
				t.Errorf("expected message containing %q, got %q", tc.wantMsg, resp.Results[0].Message)
			}
		})
	}
}

func TestMatchUniqueBy_NestedPath(t *testing.T) {
	eng := setOpPolicy(t, "uniqueby-nested", `path: "spec.items", uniqueBy: "metadata.name"`)

	resp := evalSetOp(t, eng, map[string]any{
		"kind": "List",
		"spec": map[string]any{"items": []any{
			map[string]any{"metadata": map[string]any{"name": "a"}},
			map[string]any{"metadata": map[string]any{"name": "a"}},
		}},
	})
	if resp.Decision != DecisionDeny {
		t.Errorf("expected deny for nested-path duplicates, got %s", resp.Decision)
	}
}

func TestMatchSorted(t *testing.T) {
	asc := setOpPolicy(t, "sorted-asc", `path: "spec.priorities", sorted: "asc"`)
	desc := setOpPolicy(t, "sorted-desc", `path: "spec.versions", sorted: "desc"`)

	ascCases := []struct {
		name   string
		values []any
		want   Decision
	}{
		{"ascending numbers", []any{1, 2, 3}, DecisionAllow},
		{"equal neighbors allowed", []any{1, 2, 2, 3}, DecisionAllow},
		{"unsorted numbers", []any{3, 1, 2}, DecisionDeny},
		{"ascending strings", []any{"alpha", "beta", "gamma"}, DecisionAllow},
		{"single element", []any{7}, DecisionAllow},
		{"empty array", []any{}, DecisionAllow},
	}
	for _, tc := range ascCases {
		t.Run("asc/"+tc.name, func(t *testing.T) {
			resp := evalSetOp(t, asc, map[string]any{
				"kind": "Queue",
				"spec": map[string]any{"priorities": tc.values},
			})
			if resp.Decision != tc.want {
				t.Errorf("%v: expected %s, got %s", tc.values, tc.want, resp.Decision)
			}
		})
	}

	t.Run("desc numbers", func(t *testing.T) {
		resp := evalSetOp(t, desc, map[string]any{
			"kind": "Release",
			"spec": map[string]any{"versions": []any{3, 2, 1}},
		})
		if resp.Decision != DecisionAllow {
			t.Errorf("expected allow for descending, got %s", resp.Decision)
		}
		resp = evalSetOp(t, desc, map[string]any{
			"kind": "Release",
			"spec": map[string]any{"versions": []any{1, 2, 3}},
		})
		if resp.Decision != DecisionDeny {
			t.Errorf("expected deny for ascending under desc, got %s", resp.Decision)
		}
	})

	t.Run("composite elements are not orderable", func(t *testing.T) {
		resp := evalSetOp(t, asc, map[string]any{
			"kind": "Queue",
			"spec": map[string]any{"priorities": []any{map[string]any{"p": 1}, map[string]any{"p": 2}}},
		})
		if resp.Decision != DecisionDeny {
			t.Errorf("expected deny for unorderable elements, got %s", resp.Decision)
		}
		if !strings.Contains(resp.Results[0].Message, "cannot be ordered") {
			t.Errorf("expected ordering diagnostic, got %q", resp.Results[0].Message)
		}
	})

	t.Run("invalid order value fails closed", func(t *testing.T) {
		bad := setOpPolicy(t, "sorted-bad", `path: "spec.priorities", sorted: "sideways"`)
		resp := evalSetOp(t, bad, map[string]any{
			"kind": "Queue",
			"spec": map[string]any{"priorities": []any{1, 2}},
		})
		if resp.Decision != DecisionDeny {
			t.Errorf("expected deny for invalid sort order, got %s", resp.Decision)
		}
	})
}

func TestMatchContainsAll(t *testing.T) {
	eng := setOpPolicy(t, "containsall-pol", `path: "spec.regions", containsAll: ["us-east-1", "eu-west-1"]`)

	cases := []struct {
		name    string
		regions []any
		want    Decision
		wantMsg string
	}{
		{"exact required set", []any{"us-east-1", "eu-west-1"}, DecisionAllow, ""},
		{"superset", []any{"us-east-1", "eu-west-1", "ap-south-1"}, DecisionAllow, ""},
		{"missing one", []any{"us-east-1"}, DecisionDeny, "missing required values: [eu-west-1]"},
		{"empty array", []any{}, DecisionDeny, "missing required values"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evalSetOp(t, eng, map[string]any{
				"kind": "Deployment",
				"spec": map[string]any{"regions": tc.regions},
			})
			if resp.Decision != tc.want {
				t.Fatalf("regions %v: expected %s, got %s", tc.regions, tc.want, resp.Decision)
			}
			if tc.wantMsg != "" && !strings.Contains(resp.Results[0].Message, tc.wantMsg) {
				t.Errorf("expected message containing %q, got %q", tc.wantMsg, resp.Results[0].Message)
			}
		})
	}
}

func TestMatchSubsetOf(t *testing.T) {
	eng := setOpPolicy(t, "subsetof-pol", `path: "spec.zones", subsetOf: ["zone-a", "zone-b", "zone-c"]`)

	cases := []struct {
		name  string
		zones []any
		want  Decision
	}{
		{"proper subset", []any{"zone-a", "zone-c"}, DecisionAllow},
		{"full set", []any{"zone-a", "zone-b", "zone-c"}, DecisionAllow},
		{"disallowed value", []any{"zone-a", "zone-x"}, DecisionDeny},
		{"empty array", []any{}, DecisionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := evalSetOp(t, eng, map[string]any{
				"kind": "Deployment",
				"spec": map[string]any{"zones": tc.zones},
			})
			if resp.Decision != tc.want {
				t.Errorf("zones %v: expected %s, got %s", tc.zones, tc.want, resp.Decision)
			}
		})
	}
}

func TestMatchSetOperators_PathNotFound(t *testing.T) {
	for _, matchBlock := range []string{
		`path: "spec.missing", unique: true`,
		`path: "spec.missing", uniqueBy: "name"`,
		`path: "spec.missing", sorted: "asc"`,
		`path: "spec.missing", containsAll: ["a"]`,
		`path: "spec.missing", subsetOf: ["a"]`,
	} {
		eng := setOpPolicy(t, "missing-path", matchBlock)
		resp := evalSetOp(t, eng, map[string]any{"kind": "Thing", "spec": map[string]any{}})
		if resp.Decision != DecisionDeny {
			t.Errorf("%s: expected deny for missing path, got %s", matchBlock, resp.Decision)
		}
		if !strings.Contains(resp.Results[0].Message, "not found") {
			t.Errorf("%s: expected not-found diagnostic, got %q", matchBlock, resp.Results[0].Message)
		}
	}
}
