package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/client"
	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/health"
	"github.com/infrashift/garmr/internal/observability"
)

// integrationServer sets up a minimal server with an engine for integration tests.
// Returns the httptest server and the engine for policy management.
func integrationServer(t *testing.T, apiKey string) (*httptest.Server, *engine.Engine) {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	obs := observability.NewProvider()
	eng.SetObservability(obs)

	healthHandler := health.NewHandler("0.1.0-test")

	mux := http.NewServeMux()
	healthHandler.RegisterRoutes(mux)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"healthy": true, "version": "0.1.0-test"})
	})
	mux.HandleFunc("/v1/evaluate", makeEvaluateHandler(eng, obs))
	mux.HandleFunc("/v1/policies", makePoliciesHandler(eng))

	var handler http.Handler = mux

	// Auth middleware
	if apiKey != "" {
		handler = authMiddleware(apiKey, mux)
	}

	ts := httptest.NewServer(handler)
	return ts, eng
}

func makeEvaluateHandler(eng *engine.Engine, obs *observability.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Input     map[string]any `json:"input"`
			Namespace string         `json:"namespace"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Input == nil {
			http.Error(w, "input is required", http.StatusBadRequest)
			return
		}

		result, err := eng.Evaluate(r.Context(), &engine.EvaluateRequest{
			Input:     req.Input,
			Namespace: req.Namespace,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]any{
			"decision":   string(result.Decision),
			"request_id": "integration-test",
			"results":    make([]map[string]any, len(result.Results)),
			"metrics": map[string]any{
				"policies_evaluated": result.Metrics.PoliciesEvaluated,
				"rules_evaluated":    result.Metrics.RulesEvaluated,
			},
		}
		for i, r := range result.Results {
			resp["results"].([]map[string]any)[i] = map[string]any{
				"policy_name": r.PolicyName,
				"rule_id":     r.RuleID,
				"passed":      r.Passed,
				"message":     r.Message,
				"severity":    string(r.Severity),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func makePoliciesHandler(eng *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		namespace := r.URL.Query().Get("namespace")
		policies := eng.ListPolicies(namespace)
		list := make([]map[string]any, len(policies))
		for i, p := range policies {
			list[i] = map[string]any{
				"name":       p.Name,
				"namespace":  p.Namespace,
				"rule_count": len(p.Rules),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"policies": list})
	}
}

func authMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/livez" {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key != apiKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

const passingPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "pass-policy"
	namespace: "default"
}
spec: {
	description: "Policy that passes"
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

const failingPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "fail-policy"
	namespace: "default"
}
spec: {
	description: "Policy that fails"
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

const warnPolicy = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "warn-policy"
	namespace: "default"
}
spec: {
	description: "Policy with warn enforcement"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "check"
		severity:    "low"
		expr: {match: {path: "x", equals: 1}}
		message:     "advisory"
	}]
	enforcement: action: "warn"
}
`

// --- Full Allow Flow ---

func TestIntegration_AllowFlow(t *testing.T) {
	ts, eng := integrationServer(t, "")
	defer ts.Close()

	eng.LoadPolicy(context.Background(), "pass-policy", "default", passingPolicy)

	c, _ := client.NewClient(client.Config{Address: ts.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{
		"status": "active",
	}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

// --- Full Deny Flow ---

func TestIntegration_DenyFlow(t *testing.T) {
	ts, eng := integrationServer(t, "")
	defer ts.Close()

	eng.LoadPolicy(context.Background(), "fail-policy", "default", failingPolicy)

	c, _ := client.NewClient(client.Config{Address: ts.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{
		"env": "staging",
	}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny, got %s", result.Decision)
	}
	if len(result.Results) == 0 {
		t.Error("expected violation results")
	}
}

// --- Full Warn Flow ---

func TestIntegration_WarnFlow(t *testing.T) {
	ts, eng := integrationServer(t, "")
	defer ts.Close()

	eng.LoadPolicy(context.Background(), "warn-policy", "default", warnPolicy)

	c, _ := client.NewClient(client.Config{Address: ts.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{
		"x": 999,
	}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "warn" {
		t.Errorf("expected warn, got %s", result.Decision)
	}
}

// --- CLI Exit Code Mapping ---

// Exit codes map directly from decision with no client-side overrides:
// deny → 1, everything else → 0. Warns are advisory by policy design;
// teams that want warnings to gate CI should set enforcement.action=deny
// in the policy itself rather than reinterpreting the decision in the CLI.
func TestExitCodeMapping(t *testing.T) {
	tests := []struct {
		decision string
		exitCode int
	}{
		{"allow", 0},
		{"deny", 1},
		{"warn", 0},
	}
	for _, tt := range tests {
		code := decisionToExitCode(tt.decision)
		if code != tt.exitCode {
			t.Errorf("decision=%s → exit %d, want %d", tt.decision, code, tt.exitCode)
		}
	}
}

func decisionToExitCode(decision string) int {
	if decision == "deny" {
		return 1
	}
	return 0
}

// --- Namespace Filtering End-to-End ---

func TestIntegration_NamespaceFiltering(t *testing.T) {
	ts, eng := integrationServer(t, "")
	defer ts.Close()

	policy1 := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "ns1-policy"
	namespace: "ns1"
}
spec: {
	description: "ns1 policy"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "check"
		severity:    "high"
		expr: {match: {path: "x", equals: 1}}
		message:     "x must be 1"
	}]
	enforcement: action: "deny"
}
`
	policy2 := `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "ns2-policy"
	namespace: "ns2"
}
spec: {
	description: "ns2 policy"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "check"
		severity:    "high"
		expr: {match: {path: "x", equals: 1}}
		message:     "x must be 1"
	}]
	enforcement: action: "deny"
}
`

	eng.LoadPolicy(context.Background(), "ns1-policy", "ns1", policy1)
	eng.LoadPolicy(context.Background(), "ns2-policy", "ns2", policy2)

	c, _ := client.NewClient(client.Config{Address: ts.URL})

	// Evaluate in ns1 only — x=2 should fail only ns1-policy
	result, err := c.Evaluate(context.Background(), map[string]any{
		"x": 2,
	}, client.EvaluateOptions{Namespace: "ns1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny in ns1, got %s", result.Decision)
	}
	if result.Metrics.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", result.Metrics.PoliciesEvaluated)
	}
}

// --- Policy Reload End-to-End ---

func TestIntegration_PolicyReload(t *testing.T) {
	ts, eng := integrationServer(t, "")
	defer ts.Close()

	// Initially no policies: with fail-closed defaults this returns deny
	// plus a synthetic "no policies loaded" result.
	c, _ := client.NewClient(client.Config{Address: ts.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{"x": 1}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny before any policy is loaded, got %s", result.Decision)
	}

	// Load a policy
	eng.LoadPolicy(context.Background(), "pass-policy", "default", passingPolicy)

	// Now evaluate — should use the new policy
	result, err = c.Evaluate(context.Background(), map[string]any{
		"status": "active",
	}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

// --- Auth End-to-End ---

func TestIntegration_Auth(t *testing.T) {
	ts, eng := integrationServer(t, "test-api-key")
	defer ts.Close()

	eng.LoadPolicy(context.Background(), "pass-policy", "default", passingPolicy)

	// Without API key → 401
	c, _ := client.NewClient(client.Config{Address: ts.URL})
	_, err := c.Evaluate(context.Background(), map[string]any{
		"status": "active",
	}, client.EvaluateOptions{})
	if err == nil {
		t.Error("expected error without API key")
	}

	// With correct API key → success (manual request)
	body, _ := json.Marshal(map[string]any{
		"input": map[string]any{"status": "active"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with API key, got %d", resp.StatusCode)
	}

	// Health should be exempt
	healthResp, _ := http.Get(ts.URL + "/health")
	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for health (auth exempt), got %d", healthResp.StatusCode)
	}
	healthResp.Body.Close()
}

// --- Multiple Policies ---

func TestIntegration_MultiplePolicies(t *testing.T) {
	ts, eng := integrationServer(t, "")
	defer ts.Close()

	// Load 3 policies: 2 should pass, 1 should fail
	eng.LoadPolicy(context.Background(), "pass-policy", "default", passingPolicy)
	eng.LoadPolicy(context.Background(), "fail-policy", "default", failingPolicy)
	eng.LoadPolicy(context.Background(), "warn-policy", "default", warnPolicy)

	c, _ := client.NewClient(client.Config{Address: ts.URL})

	// Input that passes pass-policy (status=active) but fails fail-policy (env != production)
	result, err := c.Evaluate(context.Background(), map[string]any{
		"status": "active",
		"env":    "staging",
		"x":      1.0,
	}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// fail-policy has deny enforcement, so overall should be deny
	if result.Decision != "deny" {
		t.Errorf("expected deny (at least one deny policy fails), got %s", result.Decision)
	}
}

// --- Policy Reload from Directory ---

func TestIntegration_ReloadFromDir(t *testing.T) {
	dir := t.TempDir()

	policyContent := `package policy

dir_policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "dir-policy"
		namespace: "default"
	}
	spec: {
		description: "loaded from dir"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "d1"
			description: "check status"
			severity:    "medium"
			expr: {match: {path: "status", equals: "ready"}}
			message:     "must be ready"
		}]
		enforcement: action: "deny"
	}
}
`
	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(policyContent), 0644)

	ts, eng := integrationServer(t, "")
	defer ts.Close()

	// Reload from dir
	count, err := eng.ReloadPoliciesFromDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromDir: %v", err)
	}
	if count == 0 {
		t.Fatal("expected at least 1 policy loaded")
	}

	// Evaluate against loaded policy
	c, _ := client.NewClient(client.Config{Address: ts.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{
		"status": "ready",
	}, client.EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

// --- Health Check End-to-End ---

func TestIntegration_HealthCheck(t *testing.T) {
	ts, _ := integrationServer(t, "")
	defer ts.Close()

	c, _ := client.NewClient(client.Config{Address: ts.URL})
	result, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Healthy {
		t.Error("expected healthy=true")
	}
	if result.Version != "0.1.0-test" {
		t.Errorf("expected version=0.1.0-test, got %s", result.Version)
	}
}
