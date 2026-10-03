package engine

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// snapshotTestPolicy builds a minimal valid policy for snapshot assertions.
func snapshotTestPolicy(name, namespace string) string {
	return makePolicy(name, namespace, "snapshot fixture",
		`{id: "r1", description: "check", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "x must be 1"}`,
		"deny", "")
}

// The snapshot is the readiness path's only view of the set, so it has to
// track every mutation rather than latching whatever was loaded at startup.
func TestSnapshotTracksMutations(t *testing.T) {
	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	empty := eng.PolicySetDigest()
	if eng.PolicyCount() != 0 {
		t.Fatalf("PolicyCount() = %d on a fresh engine, want 0", eng.PolicyCount())
	}

	if err := eng.LoadPolicy(ctx, "p", "default", snapshotTestPolicy("p", "default")); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	loaded := eng.PolicySetDigest()
	if eng.PolicyCount() != 1 {
		t.Errorf("PolicyCount() = %d after load, want 1", eng.PolicyCount())
	}
	if loaded == empty {
		t.Error("digest unchanged after loading a policy")
	}

	// The bug this pins: /ready reported the boot-time answer forever, so it
	// still said ready after every policy had been deleted.
	if !eng.DeletePolicy("default", "p") {
		t.Fatal("DeletePolicy reported nothing deleted")
	}
	if got := eng.PolicyCount(); got != 0 {
		t.Errorf("PolicyCount() = %d after delete, want 0", got)
	}
	if got := eng.PolicySetDigest(); got != empty {
		t.Errorf("digest after delete = %q, want the empty-set digest %q", got, empty)
	}
}

// The digest is what a CI pipeline compares across instances, so it must be
// derived from content alone — not from insertion order or replica identity.
func TestSnapshotDigestIsContentAddressed(t *testing.T) {
	digestAfter := func(load func(e *Engine)) string {
		t.Helper()
		eng, err := NewEngine(zap.NewNop())
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		load(eng)
		return eng.PolicySetDigest()
	}

	ctx := context.Background()
	forward := digestAfter(func(e *Engine) {
		if err := e.LoadPolicy(ctx, "a", "default", snapshotTestPolicy("a", "default")); err != nil {
			t.Fatalf("LoadPolicy a: %v", err)
		}
		if err := e.LoadPolicy(ctx, "b", "default", snapshotTestPolicy("b", "default")); err != nil {
			t.Fatalf("LoadPolicy b: %v", err)
		}
	})
	reverse := digestAfter(func(e *Engine) {
		if err := e.LoadPolicy(ctx, "b", "default", snapshotTestPolicy("b", "default")); err != nil {
			t.Fatalf("LoadPolicy b: %v", err)
		}
		if err := e.LoadPolicy(ctx, "a", "default", snapshotTestPolicy("a", "default")); err != nil {
			t.Fatalf("LoadPolicy a: %v", err)
		}
	})

	if forward != reverse {
		t.Errorf("digest depends on load order: %q vs %q", forward, reverse)
	}
}
