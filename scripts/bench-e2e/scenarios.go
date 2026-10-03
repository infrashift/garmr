package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A scenario is one policy set expressed twice — Garmr CUE and equivalent
// Rego — plus inputs with known answers. The rules mirror the in-process
// benchmarks (internal/engine/bench_test.go, scripts/bench-opa) so the
// end-to-end numbers line up with the engine numbers.
//
// Every violation is identified by the same string on both sides: the Garmr
// rule id and the member of OPA's deny set.
type Scenario struct {
	Name  string
	Garmr map[string]string // file name -> CUE source
	Rego  map[string]string // file name -> Rego source
	Cases []Case
	// Load is the case driven by the load phases (the allow case).
	Load *Case
}

type Case struct {
	Name string
	Body []byte // {"input": ...}, identical for both servers
	// Want is the sorted violation set; empty means allow.
	Want []string
}

// Allow-path response markers, checked with bytes.Contains under load so the
// load generator never has to decode JSON.
const (
	garmrAllowMarker = `"decision":"allow"`
	opaAllowMarker   = `{"result":[]}`
)

const imagePattern = `^registry\\.example\\.com/.+:[0-9]+\\.[0-9]+\\.[0-9]+$`

// cueSimpleRules is benchSimpleRules with the rule ids prefixed by pfx.
func cueSimpleRules(pfx string) string {
	return fmt.Sprintf(`{
			id:          "%[1]sr1"
			description: "environment is production"
			severity:    "high"
			expr: match: {path: "metadata.labels.env", equals: "prod"}
		}, {
			id:          "%[1]sr2"
			description: "region is allowed"
			severity:    "medium"
			expr: match: {path: "spec.region", in: ["us-east-1", "us-west-2", "eu-west-1"]}
		}, {
			id:          "%[1]sr3"
			description: "image is pinned"
			severity:    "low"
			expr: match: {path: "spec.image", pattern: "%[2]s"}
		}`, pfx, imagePattern)
}

func cuePolicy(field, name, kind, rules string) string {
	return fmt.Sprintf(`package bench

%s: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {name: %q, namespace: "default"}
	spec: {
		description: "bench"
		target: resources: [{kind: %q}]
		rules: [%s]
		enforcement: action: "deny"
	}
}
`, field, name, kind, rules)
}

// regoSimpleRules mirrors cueSimpleRules; guard is an extra body condition
// ("" for none) so kind-targeted policies can be expressed.
func regoSimpleRules(pfx, guard string) string {
	if guard != "" {
		guard += "; "
	}
	return fmt.Sprintf(`deny contains "%[1]sr1" if { %[2]sinput.metadata.labels.env != "prod" }
deny contains "%[1]sr2" if { %[2]snot input.spec.region in {"us-east-1", "us-west-2", "eu-west-1"} }
deny contains "%[1]sr3" if { %[2]snot regex.match(`+"`"+`^registry\.example\.com/.+:[0-9]+\.[0-9]+\.[0-9]+$`+"`"+`, input.spec.image) }
`, pfx, guard)
}

func simpleInput(kind string) map[string]any {
	return map[string]any{
		"kind":       kind,
		"apiVersion": "apps/v1",
		"metadata": map[string]any{
			"name":   "web",
			"labels": map[string]any{"env": "prod", "team": "payments"},
		},
		"spec": map[string]any{
			"region":   "us-east-1",
			"image":    "registry.example.com/web:1.2.3",
			"replicas": float64(3),
		},
	}
}

// violateSimple breaks all three simple rules.
func violateSimple(in map[string]any) map[string]any {
	in["metadata"].(map[string]any)["labels"].(map[string]any)["env"] = "dev"
	spec := in["spec"].(map[string]any)
	spec["region"] = "ap-south-1"
	spec["image"] = "docker.io/web:latest"
	return in
}

func body(input map[string]any) []byte {
	b, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		panic(err)
	}
	return b
}

func ids(pfx string) []string { return []string{pfx + "r1", pfx + "r2", pfx + "r3"} }

func newScenario(name string, garmr, rego map[string]string, allow, deny Case) *Scenario {
	sort.Strings(deny.Want)
	s := &Scenario{Name: name, Garmr: garmr, Rego: rego, Cases: []Case{allow, deny}}
	s.Load = &s.Cases[0]
	return s
}

func simpleScenario() *Scenario {
	return newScenario("simple",
		map[string]string{"simple.cue": cuePolicy("simple", "simple", "*", cueSimpleRules(""))},
		map[string]string{"simple.rego": "package bench\n\n" + regoSimpleRules("", "")},
		Case{Name: "allow", Body: body(simpleInput("Deployment"))},
		Case{Name: "deny", Body: body(violateSimple(simpleInput("Deployment"))), Want: ids("")},
	)
}

// manyScenario is n policies of three rules each. indexed: each policy
// targets its own kind (Garmr's kind index; OPA's rule index on input.kind)
// and the input matches one. Otherwise every policy targets "*" and all
// 3n rules apply to every request.
func manyScenario(n int, indexed bool) *Scenario {
	garmr := make(map[string]string, n)
	rego := make(map[string]string, n)
	for i := 0; i < n; i++ {
		pfx := fmt.Sprintf("p%d-", i)
		kind, guard := "*", ""
		if indexed {
			kind = fmt.Sprintf("Kind%d", i)
			guard = fmt.Sprintf("input.kind == %q", kind)
		}
		name := fmt.Sprintf("p%d", i)
		garmr[name+".cue"] = cuePolicy(name, name, kind, cueSimpleRules(pfx))
		rego[name+".rego"] = "package bench\n\n" + regoSimpleRules(pfx, guard)
	}
	target := n / 2
	kind := "Deployment"
	if indexed {
		kind = fmt.Sprintf("Kind%d", target)
	}
	var want []string
	if indexed {
		want = ids(fmt.Sprintf("p%d-", target))
	} else {
		for i := 0; i < n; i++ {
			want = append(want, ids(fmt.Sprintf("p%d-", i))...)
		}
	}
	mode := "wildcard"
	if indexed {
		mode = "indexed"
	}
	return newScenario(fmt.Sprintf("many-%s-%d", mode, n), garmr, rego,
		Case{Name: "allow", Body: body(simpleInput(kind))},
		Case{Name: "deny", Body: body(violateSimple(simpleInput(kind))), Want: want},
	)
}

// forEachScenario mirrors BenchmarkForEach_LargeInput: 50 iterated
// elements alongside 200 padding objects.
func forEachScenario() *Scenario {
	input := func(bad bool) map[string]any {
		padding := make(map[string]any, 200)
		for i := 0; i < 200; i++ {
			padding[fmt.Sprintf("key%d", i)] = map[string]any{"a": i, "b": "some padding value"}
		}
		entries := make([]any, 50)
		for i := range entries {
			entries[i] = map[string]any{"enabled": !(bad && i == 37)}
		}
		return map[string]any{"kind": "Big", "padding": padding, "entries": entries}
	}
	rules := `{
			id:          "r1"
			description: "all entries enabled"
			severity:    "low"
			expr: forEach: {
				path: "entries"
				as:   "entry"
				condition: match: {path: "entry.enabled", equals: true}
			}
		}`
	return newScenario("foreach-50",
		map[string]string{"foreach.cue": cuePolicy("foreach", "foreach", "*", rules)},
		map[string]string{"foreach.rego": "package bench\n\ndeny contains \"r1\" if { some e in input.entries; e.enabled != true }\n"},
		Case{Name: "allow", Body: body(input(false))},
		Case{Name: "deny", Body: body(input(true)), Want: []string{"r1"}},
	)
}

// inputSizeScenario is the simple policy with the input padded to roughly
// size bytes, isolating per-byte costs (body read, JSON decode, input walk).
func inputSizeScenario(label string, size int) *Scenario {
	pad := func(in map[string]any) map[string]any {
		// Each entry encodes to ~45 bytes.
		n := size / 45
		padding := make(map[string]any, n)
		for i := 0; i < n; i++ {
			padding[fmt.Sprintf("key%06d", i)] = map[string]any{"a": i, "b": "padding value"}
		}
		in["padding"] = padding
		return in
	}
	s := simpleScenario()
	s.Name = "input-" + label
	s.Cases[0].Body = body(pad(simpleInput("Deployment")))
	s.Cases[1].Body = body(pad(violateSimple(simpleInput("Deployment"))))
	return s
}

// write lays the scenario's policies out under dir/{garmr,opa}.
func (s *Scenario) write(dir string) (garmrDir, opaDir string, err error) {
	garmrDir = filepath.Join(dir, s.Name, "garmr")
	opaDir = filepath.Join(dir, s.Name, "opa")
	for d, files := range map[string]map[string]string{garmrDir: s.Garmr, opaDir: s.Rego} {
		if err := os.RemoveAll(d); err != nil {
			return "", "", err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", "", err
		}
		for name, src := range files {
			if err := os.WriteFile(filepath.Join(d, name), []byte(src), 0o644); err != nil {
				return "", "", err
			}
		}
	}
	return garmrDir, opaDir, nil
}

// checkResponse compares a decoded response's violation set with want.
func checkResponse(kind string, resp []byte, want []string) error {
	var got []string
	switch kind {
	case "garmr":
		var r struct {
			Decision string `json:"decision"`
			Results  []struct {
				RuleID string `json:"rule_id"`
				Passed bool   `json:"passed"`
			} `json:"results"`
		}
		if err := json.Unmarshal(resp, &r); err != nil {
			return fmt.Errorf("decode: %w: %.200s", err, resp)
		}
		for _, res := range r.Results {
			if !res.Passed {
				got = append(got, res.RuleID)
			}
		}
		wantDecision := "allow"
		if len(want) > 0 {
			wantDecision = "deny"
		}
		if r.Decision != wantDecision {
			return fmt.Errorf("decision = %q, want %q", r.Decision, wantDecision)
		}
	case "opa":
		var r struct {
			Result []string `json:"result"`
		}
		if err := json.Unmarshal(resp, &r); err != nil {
			return fmt.Errorf("decode: %w: %.200s", err, resp)
		}
		got = r.Result
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return fmt.Errorf("violations = %s, want %s", abbrev(got), abbrev(want))
	}
	return nil
}

func abbrev(s []string) string {
	if len(s) > 6 {
		return fmt.Sprintf("[%s ... (%d total)]", strings.Join(s[:6], " "), len(s))
	}
	return fmt.Sprintf("%v", s)
}
