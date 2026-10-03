package engine

import "testing"

func TestEqValues(t *testing.T) {
	tests := []struct {
		a, b any
		want bool
	}{
		{1.0, 1.0, true},
		{1.0, 1, true},
		{int64(2), 2.0, true},
		{"hello", "hello", true},
		{1.0, 2.0, false},
		{"a", "b", false},
		{nil, nil, true},
		{[]any{1, "a"}, []any{1.0, "a"}, true},
		{map[string]any{"k": 1}, map[string]any{"k": 1.0}, true},
		{map[string]any{"k": 1}, map[string]any{"k": 2}, false},
		// Strict typing: these all compared equal under the old %v
		// fallback, and "1" == 1 under its string-to-float parse.
		{"1", 1, false},
		{true, "true", false},
		{nil, "<nil>", false},
		{[]any{1, 2}, "[1 2]", false},
		{"", nil, false},
	}
	for _, tt := range tests {
		if got := eqValues(tt.a, tt.b); got != tt.want {
			t.Errorf("eqValues(%#v, %#v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
		if tt.want && setKey(tt.a) != setKey(tt.b) {
			t.Errorf("setKey(%#v) != setKey(%#v) for equal values", tt.a, tt.b)
		}
		if !tt.want && setKey(tt.a) == setKey(tt.b) {
			t.Errorf("setKey(%#v) == setKey(%#v) for unequal values", tt.a, tt.b)
		}
	}
}

func TestMatchesPatternCached(t *testing.T) {
	e := newTestEngine(t)
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"*", "anything", true},
		{"pod*", "pod-123", true},
		{"exact", "exact", true},
		{"exact", "other", false},
		{"*.apps", "deploy.apps", true},
	}
	for _, tt := range tests {
		if got := e.matchesPatternCached(tt.pattern, tt.value); got != tt.want {
			t.Errorf("matchesPatternCached(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestGetStringField(t *testing.T) {
	m := map[string]any{
		"metadata": map[string]any{
			"name": "test",
		},
	}
	if got := NestedString(m, "metadata", "name"); got != "test" {
		t.Errorf("expected 'test', got %q", got)
	}
	if got := NestedString(m, "metadata", "missing"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	if got := NestedString(m, "nonexistent", "name"); got != "" {
		t.Errorf("expected empty for missing path, got %q", got)
	}
}
