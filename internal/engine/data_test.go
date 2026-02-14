package engine

import (
	"testing"

	"go.uber.org/zap"
)

func TestSetGetData(t *testing.T) {
	eng, _ := NewEngine(zap.NewNop())

	err := eng.SetData("", map[string]any{"env": "prod"})
	if err != nil {
		t.Fatalf("SetData failed: %v", err)
	}

	result := eng.GetData("")
	if result == nil {
		t.Error("GetData returned nil")
	}
}
