package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Multi-operator condition blocks must evaluate every specified operator and
// AND the results. Before this behavior existed, only the first operator in
// dispatch order was enforced and the rest were silently ignored (fail open).
func TestEvaluate_MultiOperator_AND(t *testing.T) {
	cases := []struct {
		name     string
		expr     string
		input    map[string]any
		allow    bool
		messages []string // substrings expected in the violation message
	}{
		{
			name:  "match pattern+hasPrefix both pass",
			expr:  `{match: {path: "name", pattern: "^[a-z-]+$", hasPrefix: "svc-"}}`,
			input: map[string]any{"name": "svc-api"},
			allow: true,
		},
		{
			name:     "match pattern passes, hasPrefix fails",
			expr:     `{match: {path: "name", pattern: "^[a-z-]+$", hasPrefix: "svc-"}}`,
			input:    map[string]any{"name": "api"},
			messages: []string{"does not have prefix 'svc-'"},
		},
		{
			name:     "match both operators fail, both reasons reported",
			expr:     `{match: {path: "name", pattern: "^[a-z-]+$", hasPrefix: "svc-"}}`,
			input:    map[string]any{"name": "API9"},
			messages: []string{"does not match pattern", "does not have prefix 'svc-'"},
		},
		{
			name:  "match numeric range in bounds",
			expr:  `{match: {path: "replicas", greaterThan: 1, lessThan: 10}}`,
			input: map[string]any{"replicas": 3.0},
			allow: true,
		},
		{
			name:     "match numeric range upper bound violated",
			expr:     `{match: {path: "replicas", greaterThan: 1, lessThan: 10}}`,
			input:    map[string]any{"replicas": 12.0},
			messages: []string{"expected < 10"},
		},
		{
			name:  "match exists+equals correct value",
			expr:  `{match: {path: "env", exists: true, equals: "prod"}}`,
			input: map[string]any{"env": "prod"},
			allow: true,
		},
		{
			// The regression that motivated AND semantics: exists used to
			// short-circuit and the equals check was never evaluated.
			name:     "match exists+equals wrong value is a violation",
			expr:     `{match: {path: "env", exists: true, equals: "prod"}}`,
			input:    map[string]any{"env": "dev"},
			messages: []string{"expected 'prod'"},
		},
		{
			name:  "length range in bounds",
			expr:  `{match: {path: "tags", length: {greaterThan: 0, lessThan: 4}}}`,
			input: map[string]any{"tags": []any{"a", "b"}},
			allow: true,
		},
		{
			name:     "length range lower bound violated",
			expr:     `{match: {path: "tags", length: {greaterThan: 0, lessThan: 4}}}`,
			input:    map[string]any{"tags": []any{}},
			messages: []string{"expected > 0"},
		},
		{
			name:  "semver range in bounds",
			expr:  `{match: {path: "version", semver: {greaterThanOrEqual: "1.0.0", lessThan: "2.0.0"}}}`,
			input: map[string]any{"version": "1.4.2"},
			allow: true,
		},
		{
			name:     "semver range upper bound violated",
			expr:     `{match: {path: "version", semver: {greaterThanOrEqual: "1.0.0", lessThan: "2.0.0"}}}`,
			input:    map[string]any{"version": "2.1.0"},
			messages: []string{"is not < 2.0.0"},
		},
		{
			name:     "semver both bounds violated is impossible, single reason",
			expr:     `{match: {path: "version", semver: {greaterThanOrEqual: "3.0.0", lessThan: "2.0.0"}}}`,
			input:    map[string]any{"version": "2.5.0"},
			messages: []string{"is not >= 3.0.0", "is not < 2.0.0"},
		},
		{
			name:  "datetime range in bounds",
			expr:  `{match: {path: "ts", datetime: {after: "2026-01-01", before: "2027-01-01"}}}`,
			input: map[string]any{"ts": "2026-06-15"},
			allow: true,
		},
		{
			name:     "datetime range upper bound violated",
			expr:     `{match: {path: "ts", datetime: {after: "2026-01-01", before: "2027-01-01"}}}`,
			input:    map[string]any{"ts": "2027-06-15"},
			messages: []string{"is not before 2027-01-01"},
		},
		{
			name:     "datetime range lower bound violated",
			expr:     `{match: {path: "ts", datetime: {after: "2026-01-01", before: "2027-01-01"}}}`,
			input:    map[string]any{"ts": "2025-06-15"},
			messages: []string{"is not after 2026-01-01"},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policyName := fmt.Sprintf("multiop-%d", i)
			// No rule message: the evaluator's own reason must surface so the
			// per-operator failure text can be asserted.
			rule := fmt.Sprintf(
				`{id: "r1", description: "multi-op", severity: "high", expr: %s}`,
				tc.expr)
			source := makePolicy(policyName, "default", "multi-operator AND", rule, "deny", "")
			eng := loadTestPolicy(t, policyName, "default", source)

			resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: tc.input})
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if tc.allow {
				if resp.Decision != DecisionAllow {
					t.Fatalf("expected allow, got %s (results: %+v)", resp.Decision, resp.Results)
				}
				return
			}

			if resp.Decision != DecisionDeny {
				t.Fatalf("expected deny, got %s", resp.Decision)
			}
			var reasons []string
			for _, res := range resp.Results {
				if !res.Passed {
					reasons = append(reasons, res.Message)
				}
			}
			joined := strings.Join(reasons, "\n")
			for _, want := range tc.messages {
				if !strings.Contains(joined, want) {
					t.Errorf("violation reasons %q missing %q", joined, want)
				}
			}
		})
	}
}
