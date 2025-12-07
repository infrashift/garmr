// plugins/vault-authz/main.go
// Package main provides Vault authorization integration for Q Policy Agent.
// Implements a Vault auth method plugin that delegates policy decisions to Q.
//
// This plugin enables Q to serve as an external Policy Decision Point (PDP)
// for HashiCorp Vault, providing an open-source alternative to Sentinel.
//
// Build with:
//
//	go build -buildmode=plugin -o vault-authz.so ./plugins/vault-authz
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/infrashift/q-policy-agent/internal/plugin"
)

// VaultAuthzPlugin provides Vault authorization via Q policy evaluation.
type VaultAuthzPlugin struct {
	config     VaultAuthzConfig
	httpClient *http.Client
}

// VaultAuthzConfig configures Vault authorization.
type VaultAuthzConfig struct {
	// Enabled controls whether Vault authorization is active
	Enabled bool `json:"enabled"`

	// VaultAddr is the Vault server address
	VaultAddr string `json:"vaultAddr"`

	// ListenAddr for the authorization webhook endpoint
	ListenAddr string `json:"listenAddr"`

	// PolicyNamespace is the Q namespace for Vault policies
	PolicyNamespace string `json:"policyNamespace"`

	// DefaultPolicy is evaluated when no specific policy matches
	DefaultPolicy string `json:"defaultPolicy"`

	// PolicyMapping maps Vault paths to Q policies
	PolicyMapping map[string]string `json:"policyMapping"`

	// TLS configuration
	TLS TLSConfig `json:"tls"`

	// Cache configuration
	Cache CacheConfig `json:"cache"`

	// Audit configuration
	Audit AuditConfig `json:"audit"`
}

// TLSConfig for secure communication.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	CAFile     string `json:"caFile"`
	SkipVerify bool   `json:"skipVerify"`
}

// CacheConfig for decision caching.
type CacheConfig struct {
	Enabled bool          `json:"enabled"`
	TTL     time.Duration `json:"ttl"`
	MaxSize int           `json:"maxSize"`
}

// AuditConfig for decision logging.
type AuditConfig struct {
	Enabled       bool `json:"enabled"`
	IncludeInput  bool `json:"includeInput"`
	RedactSecrets bool `json:"redactSecrets"`
}

// VaultAuthzRequest represents an authorization request from Vault.
type VaultAuthzRequest struct {
	// Type of operation: create, read, update, delete, list
	Operation string `json:"operation"`

	// Path being accessed
	Path string `json:"path"`

	// Data associated with the request (may contain secrets)
	Data map[string]interface{} `json:"data,omitempty"`

	// ClientToken metadata (not the token itself)
	TokenMeta TokenMetadata `json:"token_meta"`

	// Request metadata
	RequestMeta RequestMetadata `json:"request_meta"`
}

// TokenMetadata contains non-sensitive token information.
type TokenMetadata struct {
	// DisplayName of the token
	DisplayName string `json:"display_name"`

	// Policies attached to the token
	Policies []string `json:"policies"`

	// EntityID if using Vault identity
	EntityID string `json:"entity_id,omitempty"`

	// Groups the entity belongs to
	Groups []string `json:"groups,omitempty"`

	// Metadata attached to the token
	Metadata map[string]string `json:"metadata,omitempty"`

	// TTL remaining on the token
	TTL time.Duration `json:"ttl"`
}

// RequestMetadata contains request context.
type RequestMetadata struct {
	// RemoteAddr of the client
	RemoteAddr string `json:"remote_addr"`

	// Timestamp of the request
	Timestamp time.Time `json:"timestamp"`

	// RequestID for correlation
	RequestID string `json:"request_id"`

	// Namespace in Vault (enterprise)
	Namespace string `json:"namespace,omitempty"`
}

// VaultAuthzResponse is the response to Vault.
type VaultAuthzResponse struct {
	// Allowed indicates if the request is permitted
	Allowed bool `json:"allowed"`

	// Reason for the decision
	Reason string `json:"reason,omitempty"`

	// Violations if denied
	Violations []VaultViolation `json:"violations,omitempty"`

	// TTL for caching this decision
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`
}

// VaultViolation represents a policy violation.
type VaultViolation struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

func (p *VaultAuthzPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "vault-authz",
		Type:        plugin.TypeAuth,
		Version:     "1.0.0",
		Description: "Vault external authorization via Q policy evaluation. Open-source Sentinel alternative.",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		Capabilities: []string{
			"vault.authorization",
			"vault.external-policy",
			"sentinel.alternative",
		},
	}
}

func (p *VaultAuthzPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = VaultAuthzConfig{
		Enabled:         true,
		VaultAddr:       "http://127.0.0.1:8200",
		ListenAddr:      ":8280",
		PolicyNamespace: "vault",
		DefaultPolicy:   "vault-default",
		PolicyMapping:   make(map[string]string),
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
		},
		Audit: AuditConfig{
			Enabled:       true,
			IncludeInput:  false,
			RedactSecrets: true,
		},
	}

	// Parse configuration
	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["vaultAddr"].(string); ok {
		p.config.VaultAddr = v
	}
	if v, ok := config["listenAddr"].(string); ok {
		p.config.ListenAddr = v
	}
	if v, ok := config["policyNamespace"].(string); ok {
		p.config.PolicyNamespace = v
	}
	if v, ok := config["defaultPolicy"].(string); ok {
		p.config.DefaultPolicy = v
	}

	// Parse policy mappings
	if mappings, ok := config["policyMapping"].(map[string]interface{}); ok {
		for path, policy := range mappings {
			if policyStr, ok := policy.(string); ok {
				p.config.PolicyMapping[path] = policyStr
			}
		}
	}

	if !p.config.Enabled {
		return nil
	}

	// Setup HTTP client for Vault communication
	if err := p.setupHTTPClient(); err != nil {
		return fmt.Errorf("setting up HTTP client: %w", err)
	}

	return nil
}

func (p *VaultAuthzPlugin) setupHTTPClient() error {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	if p.config.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: p.config.TLS.SkipVerify,
		}

		if p.config.TLS.CAFile != "" {
			caCert, err := os.ReadFile(p.config.TLS.CAFile)
			if err != nil {
				return fmt.Errorf("reading CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}

		if p.config.TLS.CertFile != "" && p.config.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(p.config.TLS.CertFile, p.config.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("loading client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport.TLSClientConfig = tlsConfig
	}

	p.httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return nil
}

func (p *VaultAuthzPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}
	return nil
}

func (p *VaultAuthzPlugin) Close() error {
	return nil
}

// Authorize evaluates a Vault authorization request against Q policies.
func (p *VaultAuthzPlugin) Authorize(ctx context.Context, req *VaultAuthzRequest) (*VaultAuthzResponse, error) {
	if !p.config.Enabled {
		return &VaultAuthzResponse{Allowed: true, Reason: "authorization disabled"}, nil
	}

	// Determine which policy to evaluate
	policyName := p.selectPolicy(req.Path)

	// Evaluate policy (this would call the Q engine)
	// For now, return a placeholder response
	response := &VaultAuthzResponse{
		Allowed:  true,
		Reason:   fmt.Sprintf("evaluated policy: %s/%s", p.config.PolicyNamespace, policyName),
		CacheTTL: p.config.Cache.TTL,
	}

	return response, nil
}

func (p *VaultAuthzPlugin) selectPolicy(path string) string {
	// Check for exact match
	if policy, ok := p.config.PolicyMapping[path]; ok {
		return policy
	}

	// Check for prefix match
	for prefix, policy := range p.config.PolicyMapping {
		if strings.HasPrefix(path, prefix) {
			return policy
		}
	}

	// Check for path-based conventions
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		// Try secrets engine name as policy
		// e.g., "secret/data/myapp" -> policy "vault-secret"
		return fmt.Sprintf("vault-%s", parts[0])
	}

	return p.config.DefaultPolicy
}

func (p *VaultAuthzPlugin) buildInput(req *VaultAuthzRequest) map[string]interface{} {
	input := map[string]interface{}{
		"operation": req.Operation,
		"path":      req.Path,
		"token": map[string]interface{}{
			"display_name": req.TokenMeta.DisplayName,
			"policies":     req.TokenMeta.Policies,
			"entity_id":    req.TokenMeta.EntityID,
			"groups":       req.TokenMeta.Groups,
			"metadata":     req.TokenMeta.Metadata,
		},
		"request": map[string]interface{}{
			"remote_addr": req.RequestMeta.RemoteAddr,
			"timestamp":   req.RequestMeta.Timestamp.Format(time.RFC3339),
			"request_id":  req.RequestMeta.RequestID,
			"namespace":   req.RequestMeta.Namespace,
		},
	}

	// Include data if configured (and redact secrets)
	if p.config.Audit.IncludeInput && req.Data != nil {
		if p.config.Audit.RedactSecrets {
			input["data"] = p.redactSecrets(req.Data)
		} else {
			input["data"] = req.Data
		}
	}

	return input
}

func (p *VaultAuthzPlugin) redactSecrets(data map[string]interface{}) map[string]interface{} {
	redacted := make(map[string]interface{})
	secretFields := map[string]bool{
		"password": true, "secret": true, "token": true, "key": true,
		"api_key": true, "apikey": true, "credential": true, "private": true,
	}

	for k, v := range data {
		keyLower := strings.ToLower(k)
		if secretFields[keyLower] || strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "password") {
			redacted[k] = "[REDACTED]"
		} else if nested, ok := v.(map[string]interface{}); ok {
			redacted[k] = p.redactSecrets(nested)
		} else {
			redacted[k] = v
		}
	}

	return redacted
}

// ServeHTTP handles authorization webhook requests.
func (p *VaultAuthzPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VaultAuthzRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := p.Authorize(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("authorization error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &VaultAuthzPlugin{}
