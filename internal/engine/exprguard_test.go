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

// TestExpr_UnknownOperatorRejectedAtLoad is the regression test for the typo
// class. A misspelled operator used to fall through to a raw CUE constraint
// over the (open) input, which simply gained a field and passed — a typo made
// a security rule pass unconditionally. Expressions are now typed, so a typo
// anywhere in the tree, including under `not`, is refused when the policy
// loads.
func TestExpr_UnknownOperatorRejectedAtLoad(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"misspelled match", `{mach: {path: "spec.replicas", equals: 1}}`},
		{"misspelled compare", `{comparee: {left: {path: "a"}, op: "==", right: {literal: 1}}}`},
		{"misspelled forEach", `{foreach: {path: "spec.items", as: "i", condition: {match: {path: "i", exists: true}}}}`},
		{"misspelled match operator", `{match: {path: "spec.replicas", greaterThen: 1}}`},
		{"nested inside all", `{all: [{mach: {path: "spec.replicas", equals: 1}}]}`},
		{"nested inside any", `{any: [{mach: {path: "spec.replicas", equals: 1}}]}`},
		{"nested inside not", `{not: {mach: {path: "spec.replicas", equals: 1}}}`},
		{"nested inside forEach", `{forEach: {path: "spec.items", condition: {mach: {path: "item", equals: 1}}}}`},
		{"two operators", `{match: {path: "a", equals: 1}, compare: {left: {path: "a"}, op: "==", right: {literal: 1}}}`},
		{"empty expression", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := fmt.Sprintf(`{id: "r1", description: "d", severity: "critical", expr: %s}`, tt.expr)
			src := makePolicy("p", "default", "d", rule, "deny", "")
			eng := newTestEngine(t)
			if err := eng.LoadPolicy(context.Background(), "p", "default", src); err == nil {
				t.Fatal("policy loaded; a malformed expression must be rejected")
			}
			if errs, _ := eng.Validate(src); len(errs) == 0 {
				t.Error("Validate accepted a policy the loader rejects")
			}
		})
	}
}

// TestExpr_RawConstraintRejected pins the removal of raw CUE constraints
// (`expr: {spec: replicas: <=3}`): evaluation no longer involves CUE, so an
// expression must use an operator.
func TestExpr_RawConstraintRejected(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "high", expr: {spec: replicas: <=3}}`
	src := makePolicy("p", "default", "d", rule, "deny", "")
	if err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", src); err == nil {
		t.Error("raw constraint loaded; it must be rejected")
	}
}

// TestResolveValue_EnvIsRejected pins the removal of the `{env: "NAME"}` value
// source. Violation messages interpolate resolved values back to the caller,
// so reading the server environment from a policy was a secret-exfiltration
// path reachable by any policy author. It is refused at load.
func TestResolveValue_EnvIsRejected(t *testing.T) {
	rule := `{id: "r1", description: "d", severity: "critical", expr: {compare: {left: {path: "a"}, op: "==", right: {env: "GARMR_TEST_SECRET"}}}}`
	src := makePolicy("p", "default", "d", rule, "deny", "")
	if err := newTestEngine(t).LoadPolicy(context.Background(), "p", "default", src); err == nil {
		t.Error("env value source loaded; it must be rejected")
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
