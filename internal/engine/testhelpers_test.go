package engine

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
)

// testPolicyCUE is a template for creating test policies.
// The CUE source must be a bare policy struct (no wrapping key) for LoadPolicy.
const testPolicyCUE = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "%s"
	namespace: "%s"
}
spec: {
	description: "%s"
	target: resources: [{kind: "*"}]
	rules: [%s]
	enforcement: {
		action: "%s"
		%s
	}
	%s
}
`

// makePolicy creates a CUE policy string. enfExtra goes inside enforcement{}, evalExtra goes inside spec{}.
func makePolicyFull(name, namespace, description, rules, action, enfExtra, evalExtra string) string {
	return fmt.Sprintf(testPolicyCUE, name, namespace, description, rules, action, enfExtra, evalExtra)
}

// makePolicy creates a CUE policy with the given params.
// extra goes into the spec block as evaluation config or other spec-level fields.
func makePolicy(name, namespace, description, rules, action, extra string) string {
	return makePolicyFull(name, namespace, description, rules, action, "", extra)
}

// loadTestPolicy creates a fresh engine, loads a CUE policy string, and returns the engine.
func loadTestPolicy(t *testing.T, name, namespace, source string) *Engine {
	t.Helper()
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if err := eng.LoadPolicy(context.Background(), name, namespace, source); err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	return eng
}
