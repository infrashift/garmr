package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

const reloadGoodPolicy = `package policy

good_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "good-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "RG-001"
			description: "good"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`

const reloadBrokenPolicy = `package policy

broken_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "broken-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "RB-001"
			description: "severity outside the enum"
			severity:    "catastrophic"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`

func writePolicyDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cue"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A reload that fails — broken policy or empty tree — must keep the previous
// set serving and leave the digest unchanged. Swapping in an empty set on a
// bad deploy is a silent total outage.
func TestReloadPoliciesFromDir_FailureKeepsOldSet(t *testing.T) {
	goodDir := writePolicyDir(t, reloadGoodPolicy)

	eng, _ := NewEngine(zap.NewNop())
	if err := eng.LoadPoliciesFromDir(context.Background(), goodDir); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	digest := eng.PolicySetDigest()

	cases := []struct {
		name string
		dir  string
	}{
		{"broken policy", writePolicyDir(t, reloadBrokenPolicy)},
		{"empty directory", t.TempDir()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count, err := eng.ReloadPoliciesFromDir(context.Background(), tc.dir)
			if err == nil {
				t.Fatalf("expected reload to fail, got count=%d", count)
			}

			if _, err := eng.GetPolicy("default", "good-policy"); err != nil {
				t.Errorf("old policy set was lost after failed reload: %v", err)
			}
			if got := eng.PolicySetDigest(); got != digest {
				t.Errorf("digest changed after failed reload: %s != %s", got, digest)
			}
		})
	}
}

// LoadPoliciesFromDir against a tree with zero policies must error rather
// than succeed vacuously — an empty --policy-dir is a misconfiguration and
// startup should fail fast.
func TestLoadPoliciesFromDir_EmptyDirFails(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	if err := eng.LoadPoliciesFromDir(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected loading an empty directory to fail")
	}
}

// The digest is a function of policy content only: identical trees produce
// identical digests across engines, and different content changes it.
func TestPolicySetDigest_Deterministic(t *testing.T) {
	dir := writePolicyDir(t, reloadGoodPolicy)

	engA, _ := NewEngine(zap.NewNop())
	engB, _ := NewEngine(zap.NewNop())
	if err := engA.LoadPoliciesFromDir(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if err := engB.LoadPoliciesFromDir(context.Background(), dir); err != nil {
		t.Fatal(err)
	}

	if engA.PolicySetDigest() != engB.PolicySetDigest() {
		t.Error("identical trees produced different digests")
	}
	if engA.PolicySetDigest() == "" {
		t.Error("digest is empty")
	}

	other := writePolicyDir(t, reloadGoodPolicy+`
second_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "second-policy"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "RG-002"
			description: "second"
			severity:    "low"
			expr: {match: {path: "y", equals: 2}}
		}]
		enforcement: action: "deny"
	}
}
`)
	engC, _ := NewEngine(zap.NewNop())
	if err := engC.LoadPoliciesFromDir(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if engC.PolicySetDigest() == engA.PolicySetDigest() {
		t.Error("different policy sets produced the same digest")
	}
}
