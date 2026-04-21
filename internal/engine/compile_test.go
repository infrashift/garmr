package engine

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

func TestLoadPolicy(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	source := makePolicy("test-policy", "default", "A test policy",
		`{
			id: "rule-1"
			description: "check name"
			severity: "high"
			expr: { match: { path: "name", equals: "test" } }
			message: "name must be test"
		}`,
		"deny", "")

	err = eng.LoadPolicy(context.Background(), "test-policy", "default", source)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "test-policy" {
		t.Errorf("expected name=test-policy, got %s", policies[0].Name)
	}
}

func TestLoadPolicy_InvalidSource(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())
	err := eng.LoadPolicy(context.Background(), "bad", "default", "!!! invalid CUE !!!")
	if err == nil {
		t.Error("expected error for invalid CUE source")
	}
}

func TestLoadPolicy_RejectsReservedNamespace(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())

	source := makePolicy("x", ReservedSystemNamespace, "tries to use reserved ns",
		`{id: "r1", description: "d", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "m"}`,
		"deny", "")

	err := eng.LoadPolicy(context.Background(), "x", ReservedSystemNamespace, source)
	if err == nil {
		t.Fatal("expected LoadPolicy to reject the reserved namespace")
	}
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("expected ErrInvalidPolicy, got %v", err)
	}

	// Policy must not have been stored.
	if got := eng.ListPolicies(ReservedSystemNamespace); len(got) != 0 {
		t.Errorf("expected no policies stored in reserved namespace, got %d", len(got))
	}
}
