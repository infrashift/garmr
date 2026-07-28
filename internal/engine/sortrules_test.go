package engine

import "testing"

// sortRules ordering contract, pinned before (and preserved through) the
// comparator refactor. DefinitionOrder is the universal tiebreak, rules with
// a priority sort before rules without, lower priority values first, and
// higher severities first.
func TestSortRules_Orders(t *testing.T) {
	pri := func(p int) *int { return &p }
	rules := []CompiledRule{
		{ID: "a", Severity: SeverityLow, Priority: pri(20), DefinitionOrder: 0},
		{ID: "b", Severity: SeverityCritical, DefinitionOrder: 1},
		{ID: "c", Severity: SeverityHigh, Priority: pri(10), DefinitionOrder: 2},
		{ID: "d", Severity: SeverityCritical, Priority: pri(10), DefinitionOrder: 3},
		{ID: "e", Severity: SeverityMedium, DefinitionOrder: 4},
	}

	cases := []struct {
		order EvaluationOrder
		want  []string
	}{
		// Definition: untouched.
		{EvalOrderDefinition, []string{"a", "b", "c", "d", "e"}},
		// Severity: critical first; ties (b/d critical) by definition order.
		{EvalOrderSeverity, []string{"b", "d", "c", "e", "a"}},
		// Priority: prioritized rules first (10 before 20), c/d tie broken by
		// definition order; unprioritized b/e keep definition order.
		{EvalOrderPriority, []string{"c", "d", "a", "b", "e"}},
		// Priority then severity: the c/d priority tie is broken by severity
		// (d is critical), then unprioritized rules by severity.
		{EvalOrderPriorityThenSev, []string{"d", "c", "a", "b", "e"}},
		// Unknown order falls back to priority.
		{EvaluationOrder("bogus"), []string{"c", "d", "a", "b", "e"}},
	}

	for _, tc := range cases {
		t.Run(string(tc.order), func(t *testing.T) {
			got := sortRules(rules, tc.order)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rules, want %d", len(got), len(tc.want))
			}
			for i, id := range tc.want {
				if got[i].ID != id {
					ids := make([]string, len(got))
					for j, r := range got {
						ids[j] = r.ID
					}
					t.Fatalf("order %s: got %v, want %v", tc.order, ids, tc.want)
				}
			}
			// The input slice must not be reordered.
			for i, id := range []string{"a", "b", "c", "d", "e"} {
				if rules[i].ID != id {
					t.Fatal("sortRules mutated its input slice")
				}
			}
		})
	}
}
