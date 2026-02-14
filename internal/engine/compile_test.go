package engine

import (
	"context"
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
