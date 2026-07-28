package engine

import "testing"

func TestValuesEqual(t *testing.T) {
	tests := []struct {
		a, b any
		want bool
	}{
		{1.0, 1.0, true},
		{1.0, 1, true},
		{"hello", "hello", true},
		{1.0, 2.0, false},
		{"a", "b", false},
	}
	for _, tt := range tests {
		if got := valuesEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("valuesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
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

func TestGetMapField(t *testing.T) {
	m := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				"app": "nginx",
			},
		},
	}
	labels := getMapField(m, "metadata", "labels")
	if labels == nil {
		t.Fatal("expected non-nil labels")
	}
	if labels["app"] != "nginx" {
		t.Errorf("expected app=nginx, got %s", labels["app"])
	}
}
