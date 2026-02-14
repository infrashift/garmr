package engine

import (
	"testing"

	"go.uber.org/zap"
)

func TestNewEngine(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if eng == nil {
		t.Fatal("engine is nil")
	}
	if len(eng.builtins) == 0 {
		t.Error("no builtins registered")
	}
}

func TestNewEngine_NilLogger(t *testing.T) {
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine with nil logger failed: %v", err)
	}
	if eng == nil {
		t.Fatal("engine is nil")
	}
}
