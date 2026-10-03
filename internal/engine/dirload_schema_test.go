package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// The directory loader is the production path (--policy-dir), so it must
// enforce the same schema as garmr validate — and it must fail closed: one
// schema-invalid policy fails the whole load (nothing is published), so a bad
// deploy halts instead of shipping a partial policy set.
func TestLoadPoliciesFromDir_SchemaValidation(t *testing.T) {
	const validPolicy = `
valid_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "valid-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "OK-001"
			description: "valid"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`

	cases := []struct {
		name    string
		invalid string
	}{
		{
			name: "unknown spec field",
			invalid: `
bad_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "bad-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rulez: []
		rules: [{
			id:          "BAD-001"
			description: "typo'd rules field alongside"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`,
		},
		{
			name: "invalid severity",
			invalid: `
bad_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "bad-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "BAD-001"
			description: "severity outside the enum"
			severity:    "urgent"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`,
		},
		{
			name: "malformed metadata name",
			invalid: `
bad_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "Bad_Name"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "BAD-001"
			description: "name violates the schema regex"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`,
		},
		{
			name: "invalid enforcement action",
			invalid: `
bad_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "bad-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "BAD-001"
			description: "action outside the enum"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "block"
	}
}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			content := "package policy\n" + validPolicy + tc.invalid
			if err := os.WriteFile(filepath.Join(dir, "policies.cue"), []byte(content), 0644); err != nil {
				t.Fatal(err)
			}

			eng, _ := NewEngine(zap.NewNop())
			err := eng.LoadPoliciesFromDir(context.Background(), dir)
			if err == nil {
				t.Fatal("expected the load to fail on the schema-invalid policy")
			}
			if !strings.Contains(err.Error(), "schema validation") {
				t.Errorf("error should name schema validation, got: %v", err)
			}

			// Fail closed means nothing from the batch is published, the
			// valid policy included.
			if got := len(eng.ListPolicies("")); got != 0 {
				t.Errorf("expected zero policies loaded after failure, got %d", got)
			}
		})
	}
}
