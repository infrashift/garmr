package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// The directory loader is the production path (--policy-dir), so it must
// enforce the same schema as garmr validate. These tests feed it a package
// containing one valid policy alongside schema-invalid ones and assert the
// invalid documents are rejected while the valid one loads.
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
			if err := eng.LoadPoliciesFromDir(context.Background(), dir); err != nil {
				t.Fatalf("LoadPoliciesFromDir failed: %v", err)
			}

			if _, err := eng.GetPolicy("default", "valid-policy"); err != nil {
				t.Errorf("valid policy was not loaded: %v", err)
			}
			for _, name := range []string{"bad-policy", "Bad_Name"} {
				if _, err := eng.GetPolicy("default", name); err == nil {
					t.Errorf("schema-invalid policy %q was loaded", name)
				}
			}
		})
	}
}
