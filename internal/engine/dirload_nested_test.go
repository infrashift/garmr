package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// nestedPolicyFile renders a policy document in the on-disk file format (a
// named top-level field), as the directory loader expects.
func nestedPolicyFile(field, name string) string {
	return `package policy
` + field + `: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "` + name + `"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "R-001"
			description: "nested fixture"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`
}

// writeNestedTree builds:
//
//	root/security/base.cue          -> policy "base"
//	root/security/k8s/pod.cue       -> policy "pod"
//	root/security/k8s/rbac/role.cue -> policy "role"
//
// The shape that matters is a directory holding both policies of its own and
// subdirectories holding more.
func writeNestedTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	dirs := map[string][2]string{
		filepath.Join(root, "security"):                {"base.cue", "base"},
		filepath.Join(root, "security", "k8s"):         {"pod.cue", "pod"},
		filepath.Join(root, "security", "k8s", "rbac"): {"role.cue", "role"},
	}
	for dir, f := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", dir, err)
		}
		content := nestedPolicyFile(f[1]+"_policy", f[1])
		if err := os.WriteFile(filepath.Join(dir, f[0]), []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", f[0], err)
		}
	}
	return root
}

// The walk must not stop at the first directory that has .cue files.
//
// It used to: a subdirectory with policies of its own was loaded
// non-recursively, so anything nested below it was never visited. The load
// still succeeded (the outer directory satisfied the non-empty check), the
// server reported ready, and the nested policies were simply not enforced.
// Fail-closed startup cannot catch this — there is no error to fail on — so on
// a shared policy volume a repo restructure that nests one level deeper
// silently dropped rules from enforcement.
func TestLoadPoliciesFromDir_LoadsPoliciesBelowAPolicyDirectory(t *testing.T) {
	root := writeNestedTree(t)

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.LoadPoliciesFromDir(context.Background(), root); err != nil {
		t.Fatalf("LoadPoliciesFromDir: %v", err)
	}

	for _, name := range []string{"base", "pod", "role"} {
		if _, err := eng.GetPolicy("default", name); err != nil {
			t.Errorf("policy %q was not loaded: %v "+
				"(the walk stopped descending at a directory that had .cue files of its own)", name, err)
		}
	}
	if got := eng.PolicyCount(); got != 3 {
		t.Errorf("PolicyCount() = %d, want 3", got)
	}
}

// Reload walks the same tree, and it is the path a running server takes when
// CI updates the shared volume — so it must agree with startup exactly.
func TestReloadPoliciesFromDir_LoadsNestedPolicies(t *testing.T) {
	root := writeNestedTree(t)

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	count, err := eng.ReloadPoliciesFromDir(context.Background(), root)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromDir: %v", err)
	}
	if count != 3 {
		t.Errorf("reload loaded %d policies, want 3", count)
	}

	// Startup and reload must converge on the same digest, or a reloaded
	// instance diverges from a freshly started one.
	fresh, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := fresh.LoadPoliciesFromDir(context.Background(), root); err != nil {
		t.Fatalf("LoadPoliciesFromDir: %v", err)
	}
	if eng.PolicySetDigest() != fresh.PolicySetDigest() {
		t.Errorf("reload digest %q != startup digest %q for the same tree",
			eng.PolicySetDigest(), fresh.PolicySetDigest())
	}
}

// A nested policy that fails to compile must fail the whole load. Descending
// further would be pointless if errors down there were swallowed — the
// fail-closed guarantee has to extend to the newly reachable depth.
func TestLoadPoliciesFromDir_NestedBrokenPolicyFailsClosed(t *testing.T) {
	root := writeNestedTree(t)

	broken := filepath.Join(root, "security", "k8s", "rbac", "broken.cue")
	if err := os.WriteFile(broken, []byte(`package policy
broken_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "broken"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "R-002"
			description: "invalid severity"
			severity:    "catastrophic"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.LoadPoliciesFromDir(context.Background(), root); err == nil {
		t.Fatal("load succeeded despite a schema-invalid policy nested two levels deep")
	}

	// Nothing may be published from a failed load.
	if got := eng.PolicyCount(); got != 0 {
		t.Errorf("PolicyCount() = %d after a failed load, want 0", got)
	}
}

// The loader and the storage backend must agree on what is a policy.
//
// The backend's default excludes drop **/testdata/** and **/*_test.cue, but
// only List() consulted them — the loader is handed the backend root and
// walks it directly. Fixture trees rsynced onto a shared policy volume were
// therefore compiled and enforced while /health/deep reported them absent.
// This matters more now that the walk descends past directories that hold
// policies of their own, which is where fixture directories tend to live.
func TestLoadPoliciesFromDir_SkipsTestdataAndTestFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "security")
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	write := func(path, field, name string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(nestedPolicyFile(field, name)), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	write(filepath.Join(dir, "real.cue"), "real_policy", "real")
	write(filepath.Join(dir, "fixture_test.cue"), "fixture_policy", "fixture")
	write(filepath.Join(dir, "testdata", "sample.cue"), "sample_policy", "sample")

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.LoadPoliciesFromDir(context.Background(), root); err != nil {
		t.Fatalf("LoadPoliciesFromDir: %v", err)
	}

	if _, err := eng.GetPolicy("default", "real"); err != nil {
		t.Errorf("real policy was not loaded: %v", err)
	}
	for _, name := range []string{"fixture", "sample"} {
		if _, err := eng.GetPolicy("default", name); err == nil {
			t.Errorf("fixture policy %q was loaded and would be enforced in production", name)
		}
	}
	if got := eng.PolicyCount(); got != 1 {
		t.Errorf("PolicyCount() = %d, want 1 (fixtures must not be enforced)", got)
	}
}
