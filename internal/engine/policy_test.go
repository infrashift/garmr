package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestGetPolicy(t *testing.T) {
	source := makePolicy("my-policy", "prod", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "my-policy", "prod", source)

	p, err := eng.GetPolicy("prod", "my-policy")
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if p.Name != "my-policy" {
		t.Errorf("expected name=my-policy, got %s", p.Name)
	}

	// Not found
	_, err = eng.GetPolicy("prod", "nonexistent")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestDeletePolicy(t *testing.T) {
	source := makePolicy("del-me", "default", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	eng := loadTestPolicy(t, "del-me", "default", source)

	ok := eng.DeletePolicy("default", "del-me")
	if !ok {
		t.Error("expected DeletePolicy to return true")
	}
	if len(eng.ListPolicies("")) != 0 {
		t.Error("expected no policies after delete")
	}

	// Delete nonexistent
	ok = eng.DeletePolicy("default", "nope")
	if ok {
		t.Error("expected false for deleting nonexistent policy")
	}
}

func TestListPolicies_NamespaceFilter(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	source1 := makePolicy("p1", "ns1", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	source2 := makePolicy("p2", "ns2", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")

	eng.LoadPolicy(context.Background(), "p1", "ns1", source1)
	eng.LoadPolicy(context.Background(), "p2", "ns2", source2)

	if len(eng.ListPolicies("")) != 2 {
		t.Error("expected 2 policies total")
	}
	if len(eng.ListPolicies("ns1")) != 1 {
		t.Error("expected 1 policy in ns1")
	}
	if len(eng.ListPolicies("ns2")) != 1 {
		t.Error("expected 1 policy in ns2")
	}
	if len(eng.ListPolicies("ns3")) != 0 {
		t.Error("expected 0 policies in ns3")
	}
}

// --- Validation ---

func TestValidate_ValidPolicy(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	source := makePolicy("valid", "default", "test",
		`{id: "r1", description: "test", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`,
		"deny", "")
	errors, _ := eng.Validate(source)
	if len(errors) != 0 {
		t.Errorf("expected no errors, got %v", errors)
	}
}

func TestValidate_InvalidPolicy(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	errors, _ := eng.Validate("{ invalid cue !!! }")
	if len(errors) == 0 {
		t.Error("expected validation errors for invalid CUE")
	}
}

// --- Policy Loading from Directory ---

func TestLoadPoliciesFromDir(t *testing.T) {
	dir := t.TempDir()

	// Write a CUE file with a policy
	policyContent := `package policy

container_security: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "container-security"
		namespace: "default"
	}
	spec: {
		description: "Container security policy"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "cs-1"
			description: "check image"
			severity:    "high"
			expr: {match: {path: "image", equals: "nginx"}}
			message: "image must be nginx"
		}]
		enforcement: action: "deny"
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	eng, _ := NewEngine(zap.NewNop())
	err := eng.LoadPoliciesFromDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("LoadPoliciesFromDir failed: %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) == 0 {
		t.Error("expected at least 1 policy loaded from dir")
	}
}

func TestReloadPoliciesFromDir(t *testing.T) {
	dir := t.TempDir()

	policyContent := `package policy

test_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "test"
		namespace: "default"
	}
	spec: {
		description: "test"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "t-1"
			description: "check"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
			message: "fail"
		}]
		enforcement: action: "deny"
	}
}
`
	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(policyContent), 0644)

	eng, _ := NewEngine(zap.NewNop())
	count, err := eng.ReloadPoliciesFromDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromDir failed: %v", err)
	}
	if count == 0 {
		t.Error("expected at least 1 policy reloaded")
	}
}
