package engine

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// examplePoliciesDir is the repo's showcase policy set. Nothing else in the
// Go tree references it, so without this test the examples are shipped
// uncompiled: `cue vet` cannot substitute (the examples do not import
// schemas/, and no Go code reads schemas/ either), and `garmr validate`
// cannot either (it requires a running server).
const examplePoliciesDir = "../../example-policies"

// TestExamplePolicies_Load asserts every shipped example policy still compiles
// against the engine's embedded schema. This is the guard that catches a
// schema change silently invalidating the documentation's worked examples.
func TestExamplePolicies_Load(t *testing.T) {
	files := collectExampleCUEFiles(t)
	if len(files) == 0 {
		t.Fatalf("no example policies found under %s", examplePoliciesDir)
	}

	for _, path := range files {
		t.Run(relToExamples(path), func(t *testing.T) {
			eng := newTestEngine(t)
			names, err := eng.LoadPoliciesFromFile(context.Background(), path)
			if err != nil {
				t.Fatalf("LoadPoliciesFromFile(%s) failed: %v", path, err)
			}
			if len(names) == 0 {
				t.Errorf("LoadPoliciesFromFile(%s) loaded no policies", path)
			}
		})
	}
}

// TestExamplePolicies_LoadDir asserts the whole tree loads at once, which is
// what the server does with --policy-dir. It catches cross-file conflicts
// (duplicate namespace/name keys) that the per-file test cannot see.
func TestExamplePolicies_LoadDir(t *testing.T) {
	eng := newTestEngine(t)
	if err := eng.LoadPoliciesFromDir(context.Background(), examplePoliciesDir); err != nil {
		t.Fatalf("LoadPoliciesFromDir(%s) failed: %v", examplePoliciesDir, err)
	}
	if got := len(eng.ListPolicies("")); got == 0 {
		t.Fatal("LoadPoliciesFromDir loaded no policies")
	}
}

// collectExampleCUEFiles returns every non-test .cue file under the example
// tree. *_test.cue files carry no package clause (they are `garmr test`
// fixtures) and are skipped by the loader, so they are skipped here too.
func collectExampleCUEFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(examplePoliciesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "cue.mod" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".cue" || strings.HasSuffix(path, "_test.cue") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("example policy directory %s does not exist", examplePoliciesDir)
		}
		t.Fatalf("walking %s: %v", examplePoliciesDir, err)
	}
	return files
}

func relToExamples(path string) string {
	rel, err := filepath.Rel(examplePoliciesDir, path)
	if err != nil {
		return path
	}
	return rel
}
