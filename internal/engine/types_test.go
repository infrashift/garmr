package engine

import "testing"

// --- Severity Weights ---

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 75},
		{SeverityMedium, 50},
		{SeverityLow, 25},
		{SeverityInfo, 0},
		{Severity("unknown"), 0},
	}
	for _, tt := range tests {
		if got := tt.severity.Weight(); got != tt.want {
			t.Errorf("%s.Weight() = %d, want %d", tt.severity, got, tt.want)
		}
	}
}
