package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Load-time checks for policy fields that used to be accepted and then
// silently ignored or misapplied. Each one was fail-open: the policy loaded
// and enforced less than its author wrote.

func policyWith(spec string) string {
	return `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	target: resources: [{kind: "*"}]
` + spec + `
}`
}

const oneRule = `rules: [{id: "R1", description: "d", severity: "high", expr: match: {path: "x", equals: 1}}]`

func TestLoad_RejectsMalformedFields(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantErr string
	}{
		{
			// An expiry that did not parse left Expiry nil, and a nil expiry
			// means "never expires": a typo granted a permanent bypass.
			name: "unparseable exception expiry",
			spec: oneRule + `
enforcement: {action: "deny", exceptions: [{name: "e", reason: "r", match: {names: ["web"]}, expiry: "2026-01-01"}]}`,
			wantErr: "expiry",
		},
		{
			// Every selector field defaults to "*", so an empty match exempted
			// every input and silently disabled the policy.
			name: "exception selector with no narrowing field",
			spec: oneRule + `
enforcement: {action: "deny", exceptions: [{name: "e", reason: "r", match: {}}]}`,
			wantErr: "exception",
		},
		{
			name: "exception selector with only wildcards",
			spec: oneRule + `
enforcement: {action: "deny", exceptions: [{name: "e", reason: "r", match: {kind: "*", apiGroup: "*"}}]}`,
			wantErr: "exception",
		},
		{
			// An unparseable timeout was dropped, leaving the policy with no
			// deadline at all.
			name:    "unparseable evaluation timeout",
			spec:    oneRule + "\nenforcement: action: \"deny\"\nevaluation: timeout: \"30\"",
			wantErr: "timeout",
		},
		{
			name: "duplicate rule id",
			spec: `rules: [
	{id: "R1", description: "a", severity: "high", expr: match: {path: "x", equals: 1}},
	{id: "R1", description: "b", severity: "high", expr: match: {path: "y", equals: 1}},
]
enforcement: action: "deny"`,
			wantErr: "duplicate rule id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTestEngine(t)
			err := eng.LoadPolicy(context.Background(), "t", "default", policyWith(tt.spec))
			if err == nil {
				t.Fatal("policy loaded; it must be rejected")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
			}

			// /v1/validate must agree with the loader.
			errs, _ := eng.Validate(policyWith(tt.spec))
			if len(errs) == 0 {
				t.Error("Validate reported the policy as valid, but the loader rejects it")
			}
		})
	}
}

func TestLoad_AcceptsWellFormedExceptionAndTimeout(t *testing.T) {
	eng := newTestEngine(t)
	src := policyWith(oneRule + `
enforcement: {action: "deny", exceptions: [{name: "e", reason: "r", match: {names: ["web"]}, expiry: "2099-01-01T00:00:00Z"}]}
evaluation: timeout: "250ms"`)
	if err := eng.LoadPolicy(context.Background(), "t", "default", src); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if errs, _ := eng.Validate(src); len(errs) != 0 {
		t.Fatalf("Validate: %v", errs)
	}
}

// TestLoadDir_RejectsDuplicatePolicyKey: two files declaring the same
// namespace/name used to load with the last one silently winning.
func TestLoadDir_RejectsDuplicatePolicyKey(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"a", "b"} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "p.cue"), []byte(nestedPolicyFile("p", "same-name")), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	eng := newTestEngine(t)
	err := eng.LoadPoliciesFromDir(context.Background(), root)
	if err == nil {
		t.Fatal("load succeeded; a duplicate policy must fail the load")
	}
	if !strings.Contains(err.Error(), "default/same-name") {
		t.Errorf("error = %v, want it to name the duplicate policy", err)
	}
	if _, err := eng.ReloadPoliciesFromDir(context.Background(), root); err == nil {
		t.Error("reload succeeded; a duplicate policy must fail the reload")
	}
}

// TestTarget_APIGroupMatchesGroupOfAPIVersion: apiGroup used to be compared
// with the whole apiVersion, so apiGroup "apps" never matched "apps/v1", and
// the documented "" (core group) was treated as a wildcard.
func TestTarget_APIGroupMatchesGroupOfAPIVersion(t *testing.T) {
	tests := []struct {
		apiGroup   string
		apiVersion string
		want       bool
	}{
		{"apps", "apps/v1", true},
		{"apps", "batch/v1", false},
		{"apps", "v1", false},
		{"", "v1", true},
		{"", "apps/v1", false},
		{"*", "apps/v1", true},
		{"*", "v1", true},
		{"*.k8s.io", "networking.k8s.io/v1", true},
	}
	for _, tt := range tests {
		t.Run(tt.apiGroup+"|"+tt.apiVersion, func(t *testing.T) {
			src := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	target: resources: [{kind: "Deployment", apiGroup: "` + tt.apiGroup + `"}]
	` + oneRule + `
	enforcement: action: "deny"
}`
			eng := loadTestPolicy(t, "t", "default", src)
			resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{
				"kind": "Deployment", "apiVersion": tt.apiVersion, "x": float64(1),
			}})
			if err != nil {
				t.Fatal(err)
			}
			if got := resp.Metrics.PoliciesEvaluated == 1; got != tt.want {
				t.Errorf("matched = %v, want %v", got, tt.want)
			}
		})
	}

	// The plain-string shorthand means "this kind, any group".
	src := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	target: resources: ["Deployment"]
	` + oneRule + `
	enforcement: action: "deny"
}`
	eng := loadTestPolicy(t, "t", "default", src)
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: map[string]any{
		"kind": "Deployment", "apiVersion": "apps/v1", "x": float64(1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Metrics.PoliciesEvaluated != 1 {
		t.Error("string shorthand selector did not match a grouped apiVersion")
	}
}
