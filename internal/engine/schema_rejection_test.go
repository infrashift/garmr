package engine

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestCompile_RejectsSilentlyIgnoredFields covers three fields that were
// declared in the embedded schema and never consulted. Two of them were
// fail-open: a policy narrowed by target.conditions matched EVERYTHING, and
// enforcement.webhook implied a callout that never happened. Silently
// ignoring them is worse than refusing them, so they are rejected at compile
// time following the expr.ref precedent.
func TestCompile_RejectsSilentlyIgnoredFields(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantErrHas string
	}{
		{
			name: "target.conditions",
			source: `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	description: "d"
	target: {
		resources: [{kind: "*"}]
		conditions: [{path: "env", equals: "prod"}]
	}
	rules: [{id: "R-001", description: "d", severity: "high", expr: {match: {path: "x", exists: true}}}]
	enforcement: action: "deny"
}`,
			wantErrHas: "target.conditions is not supported",
		},
		{
			name: "enforcement.webhook",
			source: `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	description: "d"
	target: resources: [{kind: "*"}]
	rules: [{id: "R-001", description: "d", severity: "high", expr: {match: {path: "x", exists: true}}}]
	enforcement: {
		action: "deny"
		webhook: {url: "https://example.com/hook"}
	}
}`,
			wantErrHas: "enforcement.webhook is not supported",
		},
		{
			name: "rule.continueOnFail",
			source: `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	description: "d"
	target: resources: [{kind: "*"}]
	rules: [{id: "R-001", description: "d", severity: "high", expr: {match: {path: "x", exists: true}}, continueOnFail: false}]
	enforcement: action: "deny"
}`,
			wantErrHas: "'continueOnFail' is not supported",
		},
	}

	for _, tt := range tests {
		// LoadPolicy unifies with the embedded schema, so removing the field
		// from the schema is enough — it fails as "field not allowed".
		t.Run(tt.name+"/LoadPolicy", func(t *testing.T) {
			eng, err := NewEngine(zap.NewNop())
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}

			err = eng.LoadPolicy(context.Background(), "t", "default", tt.source)
			if err == nil {
				t.Fatal("LoadPolicy succeeded; the field must be rejected, not ignored")
			}
			if !strings.Contains(err.Error(), tt.wantErrHas) &&
				!strings.Contains(err.Error(), "field not allowed") {
				t.Errorf("error = %v, want the field rejected", err)
			}
		})

		// The directory loader does NOT unify with the schema (see
		// loadInstancesIntoReplica, which calls compilePolicy directly), so
		// on the production --policy-dir path the explicit compile-time
		// checks are the only thing rejecting these fields.
		//
		// That loader skips a policy it cannot compile rather than
		// propagating the reason, so what matters here is that the policy is
		// NOT loaded — a policy loaded with its targeting constraint silently
		// dropped would match everything.
		t.Run(tt.name+"/LoadPoliciesFromFile", func(t *testing.T) {
			eng, err := NewEngine(zap.NewNop())
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}

			dir := t.TempDir()
			path := dir + "/policy.cue"
			if writeErr := writeTestFile(path, "package policies\n\np: "+tt.source+"\n"); writeErr != nil {
				t.Fatalf("writing policy: %v", writeErr)
			}

			keys, err := eng.LoadPoliciesFromFile(context.Background(), path)
			if err == nil && len(keys) > 0 {
				t.Fatalf("policy loaded (%v) despite an unsupported field; it must be rejected", keys)
			}
			if got := eng.ListPolicies(""); len(got) != 0 {
				t.Errorf("engine holds %d policies after a rejected load, want 0", len(got))
			}
		})
	}
}

// TestCompile_KeepsAuthorMetadata is the counterpart: url, approvedBy and
// ticket are author metadata rather than engine mechanisms, the shipped
// examples use them, and they must keep loading.
func TestCompile_KeepsAuthorMetadata(t *testing.T) {
	source := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {name: "t", namespace: "default"}
spec: {
	description: "d"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "R-001"
		description: "d"
		severity:    "high"
		expr: {match: {path: "x", exists: true}}
		url: "https://runbooks.example.com/R-001"
	}]
	enforcement: {
		action: "deny"
		exceptions: [{
			name:       "legacy"
			reason:     "migration in flight"
			match: {kind: "Pod"}
			approvedBy: ["security-team"]
			ticket:     "SEC-1234"
		}]
	}
}`

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.LoadPolicy(context.Background(), "t", "default", source); err != nil {
		t.Fatalf("LoadPolicy rejected author metadata: %v", err)
	}
}
