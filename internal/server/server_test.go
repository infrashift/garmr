package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

const testPolicyCUE = `
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
	name:      "test-policy"
	namespace: "default"
}
spec: {
	description: "Test policy for server tests"
	target: resources: [{kind: "*"}]
	rules: [{
		id:          "r1"
		description: "check env"
		severity:    "high"
		expr: {match: {path: "env", equals: "prod"}}
		message:     "env must be prod"
	}]
	enforcement: action: "deny"
}
`

// setupTestServer creates a test server with a loaded policy.
func setupTestServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Use the real handler chain rather than re-deriving it here: a local
	// copy silently pins whatever middleware order it was written against,
	// which is how the CORS-behind-auth bug stayed invisible to these tests.
	handler := srv.Handler()

	// Mark server as ready
	srv.mu.Lock()
	srv.ready = true
	srv.mu.Unlock()

	return httptest.NewServer(handler)
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	resp.Body.Close()
	return result
}

// --- handleEvaluate ---

func TestHandleEvaluate_Allow(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "prod"},
	})

	result := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if result["decision"] != "allow" {
		t.Errorf("expected allow, got %v", result["decision"])
	}
	if result["request_id"] == nil || result["request_id"] == "" {
		t.Error("expected non-empty request_id")
	}
}

func TestHandleEvaluate_Deny(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "dev"},
	})

	result := decodeJSON(t, resp)
	if result["decision"] != "deny" {
		t.Errorf("expected deny, got %v", result["decision"])
	}
	results, ok := result["results"].([]any)
	if !ok || len(results) == 0 {
		t.Error("expected violation results")
	}
}

func TestHandleEvaluate_NoMatch_Denies(t *testing.T) {
	// Namespace filter picks no policies — fail-closed default should
	// surface DENY with a synthetic "no-match" result rather than allow.
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input":     map[string]any{"env": "prod"},
		"namespace": "does-not-exist",
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	result := decodeJSON(t, resp)
	if result["decision"] != "deny" {
		t.Fatalf("expected deny on no match, got %v", result["decision"])
	}
	results, ok := result["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("expected exactly one synthetic result, got %v", result["results"])
	}
	row := results[0].(map[string]any)
	if row["rule_id"] != "no-match" || row["policy_namespace"] != "__system__" {
		t.Errorf("synthetic result has unexpected identifiers: %+v", row)
	}
	if row["remediation"] == nil || row["remediation"] == "" {
		t.Error("synthetic result must include remediation text")
	}
}

func TestHandleEvaluate_MissingInput(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"namespace": "default",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandleEvaluate_InvalidJSON(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/evaluate", "application/json", strings.NewReader("{invalid}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandleEvaluate_WrongMethod(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/evaluate")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandleEvaluate_RequestID(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "my-custom-id")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-Request-Id") != "my-custom-id" {
		t.Errorf("expected X-Request-Id=my-custom-id, got %s", resp.Header.Get("X-Request-Id"))
	}
}

// --- handleValidate ---

func TestHandleValidate_Valid(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/validate", map[string]any{
		"policy": testPolicyCUE,
	})

	result := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if result["valid"] != true {
		t.Errorf("expected valid=true, got %v", result["valid"])
	}
}

func TestHandleValidate_Invalid(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/validate", map[string]any{
		"policy": "!!! invalid CUE !!!",
	})

	result := decodeJSON(t, resp)
	if result["valid"] != false {
		t.Errorf("expected valid=false, got %v", result["valid"])
	}
}

func TestHandleValidate_WrongMethod(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/v1/validate")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- handlePolicies ---

func TestHandlePolicies_GET(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/policies")
	if err != nil {
		t.Fatal(err)
	}
	result := decodeJSON(t, resp)
	policies, ok := result["policies"].([]any)
	if !ok {
		t.Fatal("expected policies array")
	}
	if len(policies) == 0 {
		t.Error("expected at least 1 policy")
	}

	p := policies[0].(map[string]any)
	if p["name"] != "test-policy" {
		t.Errorf("expected name=test-policy, got %v", p["name"])
	}
}

func TestHandlePolicies_GET_NamespaceFilter(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/v1/policies?namespace=nonexistent")
	result := decodeJSON(t, resp)
	policies := result["policies"].([]any)
	if len(policies) != 0 {
		t.Errorf("expected 0 policies for nonexistent namespace, got %d", len(policies))
	}
}

func TestHandlePolicies_DELETE(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/policies?name=test-policy&namespace=default", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	result := decodeJSON(t, resp)
	if result["deleted"] != true {
		t.Errorf("expected deleted=true, got %v", result["deleted"])
	}
}

func TestHandlePolicies_WrongMethod(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/policies", map[string]any{})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- handleReloadPolicies ---

func TestHandleReloadPolicies_NoPolicyDir(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/v1/policies/reload", "application/json", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for no policy dir, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHandleReloadPolicies_WithDir(t *testing.T) {
	dir := t.TempDir()

	// Write a policy file
	policyContent := `package policy

reload_test: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "reload-test"
		namespace: "default"
	}
	spec: {
		description: "reload test"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "rt-1"
			description: "check"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
			message:     "fail"
		}]
		enforcement: action: "deny"
	}
}
`
	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(policyContent), 0644)

	ts := setupTestServer(t, Config{PolicyDir: dir})
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/v1/policies/reload", "application/json", nil)
	result := decodeJSON(t, resp)
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}
	loaded, _ := result["policies_loaded"].(float64)
	if loaded == 0 {
		t.Error("expected policies_loaded > 0")
	}
}

func TestHandleReloadPolicies_WrongMethod(t *testing.T) {
	ts := setupTestServer(t, Config{PolicyDir: "/tmp"})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/v1/policies/reload")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- handleHealth / handleReady ---

func TestHandleHealth(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/health")
	result := decodeJSON(t, resp)
	if result["healthy"] != true {
		t.Errorf("expected healthy=true, got %v", result["healthy"])
	}
	if result["version"] == nil {
		t.Error("expected version field")
	}
	if result["uptime"] == nil {
		t.Error("expected uptime field")
	}
}

func TestHandleReady(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/ready")
	result := decodeJSON(t, resp)
	if result["ready"] != true {
		t.Errorf("expected ready=true, got %v", result["ready"])
	}
}

// --- Auth middleware ---

func TestAuth_NoKeyConfigured(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	// Should pass without any key
	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 (no auth), got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuth_ValidAPIKey(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret-key"})
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "secret-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with valid key, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuth_ValidBearerToken(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret-key"})
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with bearer token, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuth_MissingKey(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret-key"})
	defer ts.Close()

	resp := postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	result := decodeJSON(t, resp)
	if result["error"] == nil {
		t.Error("expected error message in response")
	}
}

func TestAuth_WrongKey(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret-key"})
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "wrong-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuth_HealthExempt(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret-key"})
	defer ts.Close()

	// Health endpoints should be exempt
	for _, path := range []string{"/health", "/ready", "/healthz", "/readyz", "/livez"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("expected %s to be auth-exempt, got 401", path)
		}
		resp.Body.Close()
	}
}

func TestAuth_CustomExemptPaths(t *testing.T) {
	ts := setupTestServer(t, Config{
		APIKey:          "secret-key",
		AuthExemptPaths: []string{"/v1/policies"},
	})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/v1/policies")
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("expected /v1/policies to be exempt")
	}
	resp.Body.Close()
}

// --- CORS middleware ---

func TestCORS_NoOrigins(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/health")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected CORS * for no origins, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	resp.Body.Close()
}

func TestCORS_SpecificOrigin(t *testing.T) {
	ts := setupTestServer(t, Config{
		CORSAllowedOrigins: []string{"http://example.com"},
	})
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/health", nil)
	req.Header.Set("Origin", "http://example.com")
	resp, _ := http.DefaultClient.Do(req)

	if resp.Header.Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Errorf("expected origin in header, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	resp.Body.Close()
}

func TestCORS_Preflight(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/v1/evaluate", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- Audit logging ---

func TestAudit_Enabled(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")

	ts := setupTestServer(t, Config{
		AuditEnabled: true,
		AuditPath:    auditPath,
	})
	defer ts.Close()

	// Make an evaluation
	postJSON(t, ts.URL+"/v1/evaluate", map[string]any{
		"input": map[string]any{"env": "prod"},
	}).Body.Close()

	// Check audit log exists
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty audit log")
	}
}
