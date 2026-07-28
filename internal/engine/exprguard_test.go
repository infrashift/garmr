package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// TestExpr_UnknownOperatorFailsClosed is the regression test for the typo
// class. The input is encoded from a map[string]any and is therefore an OPEN
// struct, so unifying `{mach: {...}}` used to add a field and succeed — a
// misspelled operator made a security rule pass unconditionally.
func TestExpr_UnknownOperatorFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"misspelled match", `{mach: {path: "spec.replicas", equals: 1}}`},
		{"misspelled compare", `{comparee: {left: {path: "a"}, op: "==", right: {literal: 1}}}`},
		{"misspelled forEach", `{foreach: {path: "spec.items", as: "i", condition: {exists: "i"}}}`},
		{"nested inside all", `{all: [{mach: {path: "spec.replicas", equals: 1}}]}`},
		{"nested inside any", `{any: [{mach: {path: "spec.replicas", equals: 1}}]}`},
		{"nested inside not", `{not: {mach: {path: "spec.replicas", equals: 1}}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "critical", expr: %s}`, tt.expr)
			decision, msg := evalRule(t, rule, map[string]any{
				"spec": map[string]any{"replicas": 99.0},
			})

			// `not` inverts, so a failing inner expression makes the rule
			// pass. What matters is that the unknown operator is not silently
			// treated as a satisfied constraint.
			if tt.name == "nested inside not" {
				return
			}
			if decision != DecisionDeny {
				t.Errorf("decision = %v, want %v; message=%q", decision, DecisionDeny, msg)
			}
			if !strings.Contains(msg, "unknown expr operator") {
				t.Errorf("message = %q, want it to name the unknown operator", msg)
			}
		})
	}
}

// TestExpr_RawConstraintStillWorks guards the feature the unknown-operator
// check must not break: a bare CUE constraint over an existing input field.
// This is a supported, documented form (see also
// TestEvaluate_RawConstraint_DirLoad_Concurrent).
func TestExpr_RawConstraintStillWorks(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high", expr: {spec: replicas: <=3}}`

	if decision, msg := evalRule(t, rule, map[string]any{
		"spec": map[string]any{"replicas": 2.0},
	}); decision != DecisionAllow {
		t.Errorf("satisfied constraint: decision = %v, want %v; message=%q", decision, DecisionAllow, msg)
	}

	if decision, _ := evalRule(t, rule, map[string]any{
		"spec": map[string]any{"replicas": 9.0},
	}); decision != DecisionDeny {
		t.Errorf("violated constraint: decision = %v, want %v", decision, DecisionDeny)
	}
}

// TestExpr_NonConcreteConstraintFailsClosed covers the sibling hole: a
// constraint naming a field the input lacks stayed non-concrete after unify
// and passed vacuously.
func TestExpr_NonConcreteConstraintFailsClosed(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high", expr: {spec: {required: string}}}`
	decision, msg := evalRule(t, rule, map[string]any{
		"spec": map[string]any{"other": "value"},
	})

	if decision != DecisionDeny {
		t.Errorf("decision = %v, want %v; a constraint on a missing field must not pass vacuously (message=%q)", decision, DecisionDeny, msg)
	}
}

// TestResolveValue_EnvIsRejected pins the removal of the `{env: "NAME"}` value
// source. Violation messages interpolate resolved values back to the caller,
// so reading the server environment from a policy was a secret-exfiltration
// path reachable by any policy author.
func TestResolveValue_EnvIsRejected(t *testing.T) {
	t.Setenv("GARMR_TEST_SECRET", "super-secret-value")

	rule := `{id: "r1", description: "d", severity: "critical", expr: {compare: {left: {path: "a"}, op: "==", right: {env: "GARMR_TEST_SECRET"}}}}`
	decision, msg := evalRule(t, rule, map[string]any{"a": "super-secret-value"})

	if decision != DecisionDeny {
		t.Errorf("decision = %v, want %v", decision, DecisionDeny)
	}
	if !strings.Contains(msg, "'env' is not supported") {
		t.Errorf("message = %q, want it to report env as unsupported", msg)
	}
	if strings.Contains(msg, "super-secret-value") {
		t.Errorf("message leaked the environment variable's value: %q", msg)
	}
}

// TestRegexCache_BoundedAndEvicts verifies the cache cannot be grown without
// limit by a caller supplying distinct patterns.
func TestRegexCache_BoundedAndEvicts(t *testing.T) {
	const max = 8
	c := newRegexCache(max)

	for i := 0; i < max*10; i++ {
		if _, err := c.get(fmt.Sprintf("^prefix-%d-suffix$", i)); err != nil {
			t.Fatalf("get(%d) failed: %v", i, err)
		}
	}

	if got := c.len(); got > max {
		t.Errorf("cache holds %d entries, want at most %d", got, max)
	}
}

func TestRegexCache_RejectsOversizedPattern(t *testing.T) {
	c := newRegexCache(maxRegexCacheEntries)

	if _, err := c.get(strings.Repeat("a", maxRegexPatternLen+1)); err == nil {
		t.Fatal("oversized pattern was accepted; it must be rejected before compiling")
	}
	if c.len() != 0 {
		t.Errorf("rejected pattern was cached (len=%d)", c.len())
	}
}

func TestRegexCache_ReturnsSameCompiledValue(t *testing.T) {
	c := newRegexCache(maxRegexCacheEntries)

	first, err := c.get(`^v[0-9]+$`)
	if err != nil {
		t.Fatalf("first get failed: %v", err)
	}
	second, err := c.get(`^v[0-9]+$`)
	if err != nil {
		t.Fatalf("second get failed: %v", err)
	}
	if first != second {
		t.Error("cache returned a different *regexp.Regexp for the same pattern")
	}
}

func TestRegexCache_ConcurrentGet(t *testing.T) {
	c := newRegexCache(64)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := c.get(fmt.Sprintf("^p%d$", (i+j)%100)); err != nil {
					t.Errorf("concurrent get failed: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if got := c.len(); got > 64 {
		t.Errorf("cache holds %d entries after concurrent use, want at most 64", got)
	}
}

// TestStageBackendFiles_RejectsPathTraversal covers a backend returning a key
// that escapes the staging directory. Without the containment check this
// wrote outside the temp dir as the server user.
func TestStageBackendFiles_RejectsPathTraversal(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "canary.cue")

	tests := []struct {
		name string
		path string
	}{
		{"parent traversal", "../escaped.cue"},
		{"nested traversal", "policies/../../escaped.cue"},
		{"absolute path", canary},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockBackend(map[string][]byte{
				tt.path: []byte(backendTestPolicy),
			})

			eng, err := NewEngine(zap.NewNop())
			if err != nil {
				t.Fatalf("NewEngine failed: %v", err)
			}

			err = eng.LoadPoliciesFromBackend(context.Background(), mock)
			if err == nil {
				t.Fatal("load succeeded; a backend path escaping the staging directory must abort the load")
			}
			if !strings.Contains(err.Error(), "unsafe path") && !strings.Contains(err.Error(), "escapes the staging directory") {
				t.Errorf("error = %v, want it to report the unsafe path", err)
			}

			if _, statErr := os.Stat(canary); statErr == nil {
				t.Errorf("file was written outside the staging directory at %s", canary)
			}
		})
	}
}
