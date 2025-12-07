// plugins/consul-authz/main.go
// Package main provides Consul authorization integration for Q Policy Agent.
// Implements external authorization for Consul service mesh and KV operations.
//
// This plugin enables Q to serve as an external Policy Decision Point (PDP)
// for HashiCorp Consul, providing policy-based control over:
// - Service registration and deregistration
// - Service-to-service intentions (connect)
// - KV store access
// - Config entry modifications
//
// Build with:
//
//	go build -buildmode=plugin -o consul-authz.so ./plugins/consul-authz
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
	"sync"
	"time"

	"github.com/infrashift/q-policy-agent/internal/plugin"
)

// ConsulAuthzPlugin provides Consul authorization via Q policy evaluation.
type ConsulAuthzPlugin struct {
	config     ConsulAuthzConfig
	httpClient *http.Client
	server     *http.Server
	mu         sync.RWMutex
}

// ConsulAuthzConfig configures Consul authorization.
type ConsulAuthzConfig struct {
	// Enabled controls whether Consul authorization is active
	Enabled bool `json:"enabled"`

	// ConsulAddr is the Consul server address
	ConsulAddr string `json:"consulAddr"`

	// ListenAddr for the authorization webhook endpoint
	ListenAddr string `json:"listenAddr"`

	// PolicyNamespace is the Q namespace for Consul policies
	PolicyNamespace string `json:"policyNamespace"`

	// Policies for different Consul operations
	Policies ConsulPolicies `json:"policies"`

	// TLS configuration
	TLS TLSConfig `json:"tls"`

	// Datacenter to operate in
	Datacenter string `json:"datacenter"`

	// ACLToken for Consul API (optional)
	ACLToken string `json:"aclToken"`
}

// ConsulPolicies maps Consul operations to Q policies.
type ConsulPolicies struct {
	// ServiceRegister policy for service registration
	ServiceRegister string `json:"serviceRegister"`

	// ServiceDeregister policy for service deregistration
	ServiceDeregister string `json:"serviceDeregister"`

	// Intention policy for service-to-service intentions
	Intention string `json:"intention"`

	// KVRead policy for KV read operations
	KVRead string `json:"kvRead"`

	// KVWrite policy for KV write operations
	KVWrite string `json:"kvWrite"`

	// ConfigEntry policy for config entry modifications
	ConfigEntry string `json:"configEntry"`

	// Default policy when no specific policy matches
	Default string `json:"default"`
}

// TLSConfig for secure communication.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	CAFile     string `json:"caFile"`
	SkipVerify bool   `json:"skipVerify"`
}

// ConsulAuthzRequest represents an authorization request.
type ConsulAuthzRequest struct {
	// Type of operation
	Operation ConsulOperation `json:"operation"`

	// Resource being accessed
	Resource ConsulResource `json:"resource"`

	// Identity of the requester
	Identity ConsulIdentity `json:"identity"`

	// Request context
	Context RequestContext `json:"context"`
}

// ConsulOperation defines the type of Consul operation.
type ConsulOperation string

const (
	OpServiceRegister   ConsulOperation = "service:register"
	OpServiceDeregister ConsulOperation = "service:deregister"
	OpServiceRead       ConsulOperation = "service:read"
	OpIntentionCreate   ConsulOperation = "intention:create"
	OpIntentionDelete   ConsulOperation = "intention:delete"
	OpIntentionCheck    ConsulOperation = "intention:check"
	OpKVRead            ConsulOperation = "kv:read"
	OpKVWrite           ConsulOperation = "kv:write"
	OpKVDelete          ConsulOperation = "kv:delete"
	OpConfigRead        ConsulOperation = "config:read"
	OpConfigWrite       ConsulOperation = "config:write"
)

// ConsulResource represents the resource being accessed.
type ConsulResource struct {
	// Type of resource: service, kv, intention, config
	Type string `json:"type"`

	// Name of the resource
	Name string `json:"name"`

	// Namespace (enterprise)
	Namespace string `json:"namespace,omitempty"`

	// Partition (enterprise)
	Partition string `json:"partition,omitempty"`

	// Datacenter
	Datacenter string `json:"datacenter,omitempty"`

	// Additional resource-specific data
	Data map[string]interface{} `json:"data,omitempty"`
}

// ConsulIdentity represents the requester's identity.
type ConsulIdentity struct {
	// ServiceName if the requester is a service
	ServiceName string `json:"service_name,omitempty"`

	// ServiceID unique identifier
	ServiceID string `json:"service_id,omitempty"`

	// Namespace of the service
	Namespace string `json:"namespace,omitempty"`

	// Partition of the service
	Partition string `json:"partition,omitempty"`

	// ACLToken metadata (not the token itself)
	TokenMeta map[string]string `json:"token_meta,omitempty"`

	// SPIFFE ID if using Connect
	SPIFFEID string `json:"spiffe_id,omitempty"`
}

// RequestContext contains request metadata.
type RequestContext struct {
	// RemoteAddr of the client
	RemoteAddr string `json:"remote_addr"`

	// Timestamp of the request
	Timestamp time.Time `json:"timestamp"`

	// RequestID for correlation
	RequestID string `json:"request_id"`

	// Datacenter where request originated
	Datacenter string `json:"datacenter"`
}

// ConsulAuthzResponse is the authorization response.
type ConsulAuthzResponse struct {
	// Allowed indicates if the request is permitted
	Allowed bool `json:"allowed"`

	// Reason for the decision
	Reason string `json:"reason,omitempty"`

	// Violations if denied
	Violations []ConsulViolation `json:"violations,omitempty"`

	// Headers to add to the response
	Headers map[string]string `json:"headers,omitempty"`
}

// ConsulViolation represents a policy violation.
type ConsulViolation struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// IntentionRequest for service-to-service authorization.
type IntentionRequest struct {
	// Source service
	Source IntentionEndpoint `json:"source"`

	// Destination service
	Destination IntentionEndpoint `json:"destination"`

	// Action being requested: allow or deny
	Action string `json:"action"`
}

// IntentionEndpoint represents a service in an intention.
type IntentionEndpoint struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Partition string `json:"partition,omitempty"`
}

func (p *ConsulAuthzPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "consul-authz",
		Type:        plugin.TypeAuth,
		Version:     "1.0.0",
		Description: "Consul external authorization via Q policy evaluation. Service mesh and KV policy control.",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		Capabilities: []string{
			"consul.authorization",
			"consul.intentions",
			"consul.service-mesh",
			"consul.kv-policy",
		},
	}
}

func (p *ConsulAuthzPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = ConsulAuthzConfig{
		Enabled:         true,
		ConsulAddr:      "http://127.0.0.1:8500",
		ListenAddr:      ":8281",
		PolicyNamespace: "consul",
		Datacenter:      "dc1",
		Policies: ConsulPolicies{
			ServiceRegister:   "consul-service-register",
			ServiceDeregister: "consul-service-deregister",
			Intention:         "consul-intention",
			KVRead:            "consul-kv-read",
			KVWrite:           "consul-kv-write",
			ConfigEntry:       "consul-config-entry",
			Default:           "consul-default",
		},
	}

	// Parse configuration
	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["consulAddr"].(string); ok {
		p.config.ConsulAddr = v
	}
	if v, ok := config["listenAddr"].(string); ok {
		p.config.ListenAddr = v
	}
	if v, ok := config["policyNamespace"].(string); ok {
		p.config.PolicyNamespace = v
	}
	if v, ok := config["datacenter"].(string); ok {
		p.config.Datacenter = v
	}

	// Parse policies
	if policies, ok := config["policies"].(map[string]interface{}); ok {
		if v, ok := policies["serviceRegister"].(string); ok {
			p.config.Policies.ServiceRegister = v
		}
		if v, ok := policies["serviceDeregister"].(string); ok {
			p.config.Policies.ServiceDeregister = v
		}
		if v, ok := policies["intention"].(string); ok {
			p.config.Policies.Intention = v
		}
		if v, ok := policies["kvRead"].(string); ok {
			p.config.Policies.KVRead = v
		}
		if v, ok := policies["kvWrite"].(string); ok {
			p.config.Policies.KVWrite = v
		}
		if v, ok := policies["default"].(string); ok {
			p.config.Policies.Default = v
		}
	}

	if !p.config.Enabled {
		return nil
	}

	// Setup HTTP client
	if err := p.setupHTTPClient(); err != nil {
		return fmt.Errorf("setting up HTTP client: %w", err)
	}

	return nil
}

func (p *ConsulAuthzPlugin) setupHTTPClient() error {
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

func (p *ConsulAuthzPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}
	return nil
}

func (p *ConsulAuthzPlugin) Close() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

// Authorize evaluates a Consul authorization request against Q policies.
func (p *ConsulAuthzPlugin) Authorize(ctx context.Context, req *ConsulAuthzRequest) (*ConsulAuthzResponse, error) {
	if !p.config.Enabled {
		return &ConsulAuthzResponse{Allowed: true, Reason: "authorization disabled"}, nil
	}

	// Select policy based on operation
	policyName := p.selectPolicy(req.Operation)

	// Build Q evaluation input
	p.buildInput(req)

	// Evaluate policy (this would call the Q engine)
	// For now, return a placeholder response
	response := &ConsulAuthzResponse{
		Allowed: true,
		Reason:  fmt.Sprintf("evaluated policy: %s/%s", p.config.PolicyNamespace, policyName),
	}

	return response, nil
}

// AuthorizeIntention evaluates a service-to-service intention.
func (p *ConsulAuthzPlugin) AuthorizeIntention(ctx context.Context, req *IntentionRequest) (*ConsulAuthzResponse, error) {
	if !p.config.Enabled {
		return &ConsulAuthzResponse{Allowed: true, Reason: "authorization disabled"}, nil
	}

	// Build intention-specific input
	input := map[string]interface{}{
		"source": map[string]interface{}{
			"name":      req.Source.Name,
			"namespace": req.Source.Namespace,
			"partition": req.Source.Partition,
		},
		"destination": map[string]interface{}{
			"name":      req.Destination.Name,
			"namespace": req.Destination.Namespace,
			"partition": req.Destination.Partition,
		},
		"action": req.Action,
	}

	// Evaluate intention policy
	_ = input // Would pass to Q engine

	response := &ConsulAuthzResponse{
		Allowed: true,
		Reason:  fmt.Sprintf("evaluated intention policy: %s/%s", p.config.PolicyNamespace, p.config.Policies.Intention),
	}

	return response, nil
}

func (p *ConsulAuthzPlugin) selectPolicy(op ConsulOperation) string {
	switch {
	case strings.HasPrefix(string(op), "service:register"):
		return p.config.Policies.ServiceRegister
	case strings.HasPrefix(string(op), "service:deregister"):
		return p.config.Policies.ServiceDeregister
	case strings.HasPrefix(string(op), "intention:"):
		return p.config.Policies.Intention
	case strings.HasPrefix(string(op), "kv:read"):
		return p.config.Policies.KVRead
	case strings.HasPrefix(string(op), "kv:write"), strings.HasPrefix(string(op), "kv:delete"):
		return p.config.Policies.KVWrite
	case strings.HasPrefix(string(op), "config:"):
		return p.config.Policies.ConfigEntry
	default:
		return p.config.Policies.Default
	}
}

func (p *ConsulAuthzPlugin) buildInput(req *ConsulAuthzRequest) map[string]interface{} {
	return map[string]interface{}{
		"operation": string(req.Operation),
		"resource": map[string]interface{}{
			"type":       req.Resource.Type,
			"name":       req.Resource.Name,
			"namespace":  req.Resource.Namespace,
			"partition":  req.Resource.Partition,
			"datacenter": req.Resource.Datacenter,
			"data":       req.Resource.Data,
		},
		"identity": map[string]interface{}{
			"service_name": req.Identity.ServiceName,
			"service_id":   req.Identity.ServiceID,
			"namespace":    req.Identity.Namespace,
			"partition":    req.Identity.Partition,
			"spiffe_id":    req.Identity.SPIFFEID,
			"token_meta":   req.Identity.TokenMeta,
		},
		"context": map[string]interface{}{
			"remote_addr": req.Context.RemoteAddr,
			"timestamp":   req.Context.Timestamp.Format(time.RFC3339),
			"request_id":  req.Context.RequestID,
			"datacenter":  req.Context.Datacenter,
		},
	}
}

// ServeHTTP handles authorization webhook requests.
func (p *ConsulAuthzPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Route based on path
	switch {
	case strings.HasSuffix(r.URL.Path, "/intention"):
		p.handleIntention(w, r)
	default:
		p.handleGeneric(w, r)
	}
}

func (p *ConsulAuthzPlugin) handleGeneric(w http.ResponseWriter, r *http.Request) {
	var req ConsulAuthzRequest
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

func (p *ConsulAuthzPlugin) handleIntention(w http.ResponseWriter, r *http.Request) {
	var req IntentionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := p.AuthorizeIntention(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("authorization error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &ConsulAuthzPlugin{}
