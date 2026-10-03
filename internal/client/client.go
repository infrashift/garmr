// internal/client/client.go
// Package client provides the Garmr HTTP client library.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client is the Garmr HTTP client.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// Config holds client configuration.
type Config struct {
	Address string
	Timeout time.Duration
}

// NewClient creates a new HTTP client.
func NewClient(cfg Config) (*Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Ensure address has scheme
	baseURL := cfg.Address
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// Validate the address so the error return means something. It used to
	// be unconditionally nil, which made `garmr health --wait` unreachable:
	// --wait only triggered on a construction failure that could never occur.
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", baseURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid server address %q: scheme must be http or https", baseURL)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid server address %q: missing host", baseURL)
	}

	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Close closes the client (no-op for HTTP client).
func (c *Client) Close() error {
	return nil
}

// EvaluateOptions configures evaluation behavior.
type EvaluateOptions struct {
	Policies      []string
	Namespace     string
	IncludePassed bool
	RequestID     string // Optional request ID for audit correlation
}

// EvaluateResult is the evaluation result.
type EvaluateResult struct {
	Decision  string       `json:"decision"`
	RequestID string       `json:"request_id"`
	Results   []RuleResult `json:"results"`
	Metrics   Metrics      `json:"metrics"`

	Summary         ResultSummary  `json:"summary"`
	EvaluationMode  EvaluationMode `json:"evaluation_mode"`
	TerminatedEarly bool           `json:"terminated_early"`
	TerminationRule *RuleResult    `json:"termination_rule,omitempty"`
}

// ResultSummary counts rule outcomes for one evaluation.
type ResultSummary struct {
	TotalRules int `json:"total_rules"`
	Passed     int `json:"passed"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
}

// EvaluationMode reports how the evaluation ran: whether dry-run or fail-fast
// applied, and how much of the rule set was actually reached.
type EvaluationMode struct {
	DryRun            bool `json:"dry_run"`
	FailFast          bool `json:"fail_fast"`
	ShortCircuited    bool `json:"short_circuited"`
	TotalRulesInScope int  `json:"total_rules_in_scope"`
	RulesEvaluated    int  `json:"rules_evaluated"`
	RulesSkipped      int  `json:"rules_skipped"`
}

// RuleResult is a single rule result.
type RuleResult struct {
	PolicyName      string `json:"policy_name"`
	PolicyNamespace string `json:"policy_namespace"`
	RuleID          string `json:"rule_id"`
	Description     string `json:"description"`
	Severity        string `json:"severity"`
	Passed          bool   `json:"passed"`
	Message         string `json:"message,omitempty"`
	Remediation     string `json:"remediation,omitempty"`
}

// Metrics contains evaluation metrics.
type Metrics struct {
	EvaluationTimeNs  int64 `json:"evaluation_time_ns"`
	PoliciesEvaluated int   `json:"policies_evaluated"`
	RulesEvaluated    int   `json:"rules_evaluated"`
}

// Evaluate evaluates input against policies.
func (c *Client) Evaluate(ctx context.Context, input map[string]interface{}, opts EvaluateOptions) (*EvaluateResult, error) {
	reqBody := map[string]interface{}{
		"input":          input,
		"namespace":      opts.Namespace,
		"policies":       opts.Policies,
		"include_passed": opts.IncludePassed,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Set request ID if provided
	if opts.RequestID != "" {
		req.Header.Set("X-Request-Id", opts.RequestID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result EvaluateResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

// EvaluateFile evaluates a JSON file against policies.
func (c *Client) EvaluateFile(ctx context.Context, path string, opts EvaluateOptions) (*EvaluateResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var input map[string]interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	return c.Evaluate(ctx, input, opts)
}

// ValidateResult is the validation result.
type ValidateResult struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty"`
}

// ValidationError is a validation error. The server reports a message and a
// coarse code (PARSE_ERROR, SCHEMA_ERROR, COMPILE_ERROR); it has no position information.
type ValidationError struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// Validate validates a policy.
func (c *Client) Validate(ctx context.Context, policy string) (*ValidateResult, error) {
	reqBody := map[string]interface{}{
		"policy": policy,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/validate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result ValidateResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

// PolicyInfo contains policy information.
type PolicyInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	RuleCount int    `json:"rule_count"`
	Hash      string `json:"hash,omitempty"`
}

// PolicyList is the /v1/policies response: the loaded policies plus the
// deterministic digest of the whole set, comparable with the output of
// `garmr policy digest` on a git checkout.
type PolicyList struct {
	Policies []PolicyInfo `json:"policies"`
	Digest   string       `json:"digest"`
	// InstanceID names the instance that answered. Behind a mesh upstream
	// every call load-balances, so this is the only way to tell one
	// instance's answer from another's.
	InstanceID string `json:"instance_id,omitempty"`
}

// ListPolicies lists all policies along with the policy-set digest.
func (c *Client) ListPolicies(ctx context.Context, namespace string) (*PolicyList, error) {
	reqURL := c.baseURL + "/v1/policies"
	if namespace != "" {
		reqURL += "?" + url.Values{"namespace": {namespace}}.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result PolicyList
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

// DeletePolicy deletes a policy. Name and namespace are query-escaped: a
// value containing `&`, `#`, `=` or a space must arrive as data, not as
// query-string structure.
func (c *Client) DeletePolicy(ctx context.Context, name, namespace string) (bool, error) {
	reqURL := c.baseURL + "/v1/policies?" + url.Values{
		"name":      {name},
		"namespace": {namespace},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, "DELETE", reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Deleted bool `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decoding response: %w", err)
	}

	return result.Deleted, nil
}

// HealthResult is the health check result.
type HealthResult struct {
	Healthy bool   `json:"healthy"`
	Version string `json:"version"`
	Uptime  string `json:"uptime"`
}

// Health checks the server health.
func (c *Client) Health(ctx context.Context) (*HealthResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result HealthResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

// ReloadResult is the policy reload result.
type ReloadResult struct {
	Success        bool   `json:"success"`
	PoliciesLoaded int    `json:"policies_loaded"`
	Digest         string `json:"digest,omitempty"`
	ReloadTimeMs   int64  `json:"reload_time_ms"`
	StorageType    string `json:"storage_type"`
	Error          string `json:"error,omitempty"`
	// InstanceID names the instance that performed this reload; convergence
	// across a fleet is checked by collecting these.
	InstanceID string `json:"instance_id,omitempty"`
}

// ReloadPolicies reloads policies from the configured directory.
func (c *Client) ReloadPolicies(ctx context.Context) (*ReloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/policies/reload", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	var result ReloadResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && result.Error == "" {
		result.Success = false
		result.Error = fmt.Sprintf("server returned status %d", resp.StatusCode)
	}

	return &result, nil
}
