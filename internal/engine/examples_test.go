package engine

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/infrashift/garmr/internal/input"
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

// TestExampleFixtures pins the decision and failing rules of every fixture
// under testdata/ against the example policies, through the same parser the
// server uses (YAML fixtures included). Nothing else evaluates these
// fixtures, so a semantic change to an operator would otherwise shift their
// outcomes silently.
func TestExampleFixtures(t *testing.T) {
	eng := newTestEngine(t)
	if err := eng.LoadPoliciesFromDir(context.Background(), examplePoliciesDir); err != nil {
		t.Fatalf("LoadPoliciesFromDir: %v", err)
	}

	tests := []struct {
		file      string
		namespace string
		policy    string
		decision  Decision
		failed    string
	}{
		{"real-world/release-pass.json", "release", "", DecisionAllow, ""},
		{"real-world/release-pass.yml", "release", "", DecisionAllow, ""},
		{"real-world/release-fail-1.yml", "release", "", DecisionWarn, "REL-003"},
		{"real-world/release-fail-3.json", "release", "", DecisionDeny, "REL-003,REL-004,REL-005"},
		{"real-world/release-fail-all.json", "release", "", DecisionDeny, "REL-001,REL-002,REL-003,REL-004,REL-005,REL-006"},
		{"real-world/k8s-pod-security-context-pass.json", "security", "", DecisionAllow, ""},
		{"real-world/k8s-pod-security-context-fail.yml", "security", "", DecisionDeny, "SEC-001,SEC-002,SEC-003,SEC-004,SEC-005,SEC-006"},
		{"real-world/cloud-resource-governance-pass.json", "cloud-governance", "", DecisionAllow, ""},
		{"real-world/cloud-resource-governance-fail.json", "cloud-governance", "", DecisionDeny, "GOV-001,GOV-003,GOV-004,GOV-005,GOV-006"},
		{"real-world/cloud-resource-governance-terraform-pass.json", "cloud-governance", "", DecisionAllow, ""},
		{"real-world/cloud-resource-governance-terraform-fail.json", "cloud-governance", "", DecisionDeny, "TF-001,TF-003,TF-004,TF-005,TF-006"},
		{"condition-operators/set-advanced-pass.json", "condition-operators", "set-advanced", DecisionAllow, ""},
		{"condition-operators/set-advanced-fail.json", "condition-operators", "set-advanced", DecisionDeny, "SET-101,SET-102,SET-103,SET-104,SET-105"},
		{"advanced-operators/compare-fail.yaml", "advanced-operators", "compare-cross-field", DecisionDeny, "CMP-101,CMP-102"},
	}

	parser := input.NewParser()
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			doc, _, err := parser.ParseFile(filepath.Join("../../testdata", tt.file))
			if err != nil {
				t.Fatalf("parsing fixture: %v", err)
			}
			req := &EvaluateRequest{Input: doc, Namespace: tt.namespace}
			if tt.policy != "" {
				req.Policies = []string{tt.policy}
			}
			resp, err := eng.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}

			failed := map[string]bool{}
			for _, r := range resp.Results {
				if !r.Passed {
					failed[r.RuleID] = true
				}
			}
			var got []string
			for id := range failed {
				got = append(got, id)
			}
			sort.Strings(got)

			if resp.Decision != tt.decision || strings.Join(got, ",") != tt.failed {
				t.Errorf("decision %s, failed [%s]; want %s, [%s]", resp.Decision, strings.Join(got, ","), tt.decision, tt.failed)
			}
		})
	}
}

// TestAggregateExample pins the worked example for projections, counted
// forEach, element-naming messages and subsetOf.
func TestAggregateExample(t *testing.T) {
	eng := newTestEngine(t)
	if _, err := eng.LoadPoliciesFromFile(context.Background(), filepath.Join(examplePoliciesDir, "advanced-operators/aggregate.cue")); err != nil {
		t.Fatal(err)
	}
	ctr := func(name string, cpu float64, privileged bool, ports ...float64) map[string]any {
		c := map[string]any{"name": name, "cpu": cpu, "securityContext": map[string]any{"privileged": privileged}}
		if len(ports) > 0 {
			var ps []any
			for _, p := range ports {
				ps = append(ps, map[string]any{"containerPort": p})
			}
			c["ports"] = ps
		}
		return c
	}
	input := map[string]any{"kind": "test-aggregate", "metadata": map[string]any{"name": "web-pod"}, "spec": map[string]any{
		"declaredPorts": []any{80.0},
		"containers":    []any{ctr("web", 2, true, 80), ctr("debug", 3, true, 9229), ctr("web", 0.5, false)},
	}}
	resp, err := eng.Evaluate(context.Background(), &EvaluateRequest{Input: input, Namespace: "advanced-operators"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range resp.Results {
		got[r.RuleID] = r.Message
	}
	want := map[string]string{
		"AGG-001": "web-pod requests more than 4 CPUs in total",
		"AGG-002": "2 containers run privileged; at most 1 may",
		"AGG-003": "container debug exposes undeclared port 9229",
		"AGG-004": "'spec.containers[*].name' contains duplicate value web",
	}
	for id, msg := range want {
		if got[id] != msg {
			t.Errorf("%s: message %q, want %q", id, got[id], msg)
		}
	}
	if len(got) != len(want) {
		t.Errorf("failed rules = %v, want exactly %v", got, want)
	}

	// AGG-005 applies only in production (`when`).
	input["metadata"].(map[string]any)["labels"] = map[string]any{"env": "prod"}
	resp, err = eng.Evaluate(context.Background(), &EvaluateRequest{Input: input, Namespace: "advanced-operators"})
	if err != nil {
		t.Fatal(err)
	}
	var agg5 string
	for _, r := range resp.Results {
		if r.RuleID == "AGG-005" {
			agg5 = r.Message
		}
	}
	if want := "production container web has no memory limit; production container debug has no memory limit"; agg5 != want {
		t.Errorf("AGG-005 in prod: message %q, want %q", agg5, want)
	}

	// SEL-001 joins services to deployments with `where`.
	bundle := map[string]any{"kind": "test-bundle",
		"services": []any{map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"selector": map[string]any{"app": "api"}}}},
		"deployments": []any{
			map[string]any{"metadata": map[string]any{"name": "web"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "web"}}}}},
			map[string]any{"metadata": map[string]any{"name": "api"}, "spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}}}},
		}}
	resp, err = eng.Evaluate(context.Background(), &EvaluateRequest{Input: bundle, Namespace: "advanced-operators"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "service web does not select the pods of deployment web"; resp.Decision != DecisionDeny || msgOf(resp) != want {
		t.Errorf("SEL-001: decision %s, message %q; want deny, %q", resp.Decision, msgOf(resp), want)
	}
}
