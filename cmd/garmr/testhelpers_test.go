// cmd/garmr/testhelpers_test.go
// Shared test fixtures for CLI integration tests.
package main

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// cobraCmd is an alias kept short for readability in fixture code.
type cobraCmd = cobra.Command

// Policy fixtures reused across command tests. Shapes match the engine's
// #Policy schema (see internal/engine).
const (
	// testDirPolicy is testPassPolicy in the on-disk format the directory
	// loader expects: a package clause and a named top-level document. The
	// bare-document form is invisible to the loader (its top-level fields are
	// apiVersion/kind/..., none of which declare kind: "Policy"), so a dir
	// seeded with it reloads to zero policies — which now fails closed.
	testDirPolicy = `package policy

pass_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "pass-policy"
		namespace: "default"
	}
	spec: {
		description: "Policy that passes when status is active"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "r1"
			description: "always pass"
			severity:    "low"
			expr: {match: {path: "status", equals: "active"}}
			message:     "status must be active"
		}]
		enforcement: action: "deny"
	}
}
`

	testPassPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "pass-policy"
	namespace: "default"
}
spec: {
	description: "Policy that passes when status is active"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "always pass"
		severity:    "low"
		expr: {match: {path: "status", equals: "active"}}
		message:     "status must be active"
	}]
	enforcement: action: "deny"
}
`

	testDenyPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "deny-policy"
	namespace: "default"
}
spec: {
	description: "Policy that denies"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "check env"
		severity:    "critical"
		expr: {match: {path: "env", equals: "production"}}
		message:     "must be production"
	}]
	enforcement: action: "deny"
}
`

	testWarnPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "warn-policy"
	namespace: "default"
}
spec: {
	description: "Advisory only"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "advisory"
		severity:    "low"
		expr: {match: {path: "x", equals: 1}}
		message:     "advisory"
	}]
	enforcement: action: "warn"
}
`

	testSecurityPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "security-check"
	namespace: "security"
}
spec: {
	description: "Security namespace policy"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "sec1"
		description: "require tls"
		severity:    "high"
		expr: {match: {path: "tls", equals: true}}
		message:     "tls required"
	}]
	enforcement: action: "deny"
}
`
)

type policyFixture struct {
	Name, Namespace, Source string
}

type testEnv struct {
	URL    string
	server *httptest.Server
	engine *engine.Engine
}

// newTestServer boots a real engine + server wrapped in httptest.
// Callers get an isolated server + cleanup; viper is reset so prior test
// state does not leak.
func newTestServer(t *testing.T, policies ...policyFixture) *testEnv {
	return newTestServerCfg(t, server.Config{}, policies...)
}

// newTestServerWithPolicyDir boots a server whose reload handler points at
// the given directory.
func newTestServerWithPolicyDir(t *testing.T, dir string, policies ...policyFixture) *testEnv {
	return newTestServerCfg(t, server.Config{PolicyDir: dir}, policies...)
}

func newTestServerCfg(t *testing.T, cfg server.Config, policies ...policyFixture) *testEnv {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for _, p := range policies {
		if loadErr := eng.LoadPolicy(context.Background(), p.Name, p.Namespace, p.Source); loadErr != nil {
			t.Fatalf("LoadPolicy %s/%s: %v", p.Namespace, p.Name, loadErr)
		}
	}

	if cfg.AuthExemptPaths == nil {
		cfg.AuthExemptPaths = []string{"/health", "/ready", "/healthz", "/readyz", "/livez", "/metrics"}
	}
	srv, err := server.NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	viper.Reset()
	viper.Set("server", ts.URL)
	viper.Set("output", "table")

	return &testEnv{URL: ts.URL, server: ts, engine: eng}
}

// captureOutput redirects os.Stdout + os.Stderr during fn, returning what
// was written to each. Command funcs print to os.Stdout directly, so cobra
// SetOut/SetErr alone is not enough.
func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()

	origOut := os.Stdout
	origErr := os.Stderr

	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = wOut
	os.Stderr = wErr

	var bufOut, bufErr bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&bufOut, rOut) }()
	go func() { defer wg.Done(); io.Copy(&bufErr, rErr) }()

	// Guard against the osExit panic sentinel so tests that trigger it
	// still get stdout/stderr back; re-panic on any other value.
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(exitPanic); !ok {
					panic(r)
				}
			}
		}()
		fn()
	}()

	wOut.Close()
	wErr.Close()
	wg.Wait()
	os.Stdout = origOut
	os.Stderr = origErr

	return bufOut.String(), bufErr.String()
}

// exitRecorder records the first osExit code and aborts execution via a
// panic sentinel so the CLI code (which assumes os.Exit does not return)
// still behaves correctly. captureOutput recovers the sentinel panic.
type exitRecorder struct {
	Code   int
	Called bool
}

type exitPanic struct{ code int }

func stubExit(t *testing.T) *exitRecorder {
	t.Helper()
	rec := &exitRecorder{Code: -1}
	orig := osExit
	osExit = func(c int) {
		if !rec.Called {
			rec.Code = c
			rec.Called = true
		}
		panic(exitPanic{c})
	}
	t.Cleanup(func() { osExit = orig })
	return rec
}

// writeTempFile writes data to a new temp file under t.TempDir.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// viperSetServer overrides the server URL viper returns, restoring the
// previous value when the test ends.
func viperSetServer(t *testing.T, url string) {
	t.Helper()
	orig := viper.GetString("server")
	viper.Set("server", url)
	t.Cleanup(func() { viper.Set("server", orig) })
}

// viperSetOutput overrides the output format, restoring previous at cleanup.
func viperSetOutput(t *testing.T, format string) {
	t.Helper()
	orig := viper.GetString("output")
	viper.Set("output", format)
	t.Cleanup(func() { viper.Set("output", orig) })
}

// mustCapture runs fn with stdout/stderr captured, returning combined output.
func mustCapture(t *testing.T, fn func()) string {
	t.Helper()
	out, err := captureOutput(t, fn)
	return out + err
}

// replaceStdin overrides /dev/stdin by redirecting os.Stdin to a pipe that
// emits the given content. Returns a restore func to be deferred.
func replaceStdin(t *testing.T, content string) func() {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatalf("write stdin pipe: %v", err)
	}
	w.Close()
	os.Stdin = r
	return func() {
		os.Stdin = orig
		r.Close()
	}
}

// flagSpec describes a cobra flag to register on a fresh test command.
type flagSpec struct {
	Kind  string // "string", "bool", "stringSlice", "duration"
	Name  string
	Value any // starting value
}

// newTestCmd returns a fresh *cobra.Command with the given flags registered.
// Callers can then use cmd.Flags().Set(...) to tweak values before invoking
// the run func. Each call returns a new command so test state does not leak.
func newTestCmd(t *testing.T, flags ...flagSpec) *cobraCmd {
	t.Helper()
	cmd := &cobraCmd{}
	for _, f := range flags {
		switch f.Kind {
		case "string":
			v, _ := f.Value.(string)
			cmd.Flags().String(f.Name, v, "")
		case "bool":
			v, _ := f.Value.(bool)
			cmd.Flags().Bool(f.Name, v, "")
		case "int":
			v, _ := f.Value.(int)
			cmd.Flags().Int(f.Name, v, "")
		case "stringSlice":
			v, _ := f.Value.([]string)
			cmd.Flags().StringSlice(f.Name, v, "")
		case "duration":
			v, _ := f.Value.(time.Duration)
			cmd.Flags().Duration(f.Name, v, "")
		default:
			t.Fatalf("unknown flag kind: %s", f.Kind)
		}
	}
	return cmd
}
