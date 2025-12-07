// internal/server/server.go
// Package server provides the HTTP server implementation.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrashift/q-policy-agent/internal/engine"
)

// Config holds server configuration.
type Config struct {
	GRPCAddr    string // Reserved for future gRPC support
	HTTPAddr    string
	PolicyDir   string
	TLSCert     string
	TLSKey      string
	EnableTLS   bool
	MaxRecvSize int
	// Audit logging
	AuditEnabled bool
	AuditPath    string
}

// Server is the Q Policy Agent server.
type Server struct {
	config      Config
	engine      *engine.Engine
	logger      *zap.Logger
	httpServer  *http.Server
	startTime   time.Time
	auditLogger *slog.Logger
	auditFile   *os.File

	mu     sync.RWMutex
	ready  bool
	checks map[string]bool
}

// NewServer creates a new server instance.
func NewServer(cfg Config, eng *engine.Engine, logger *zap.Logger) (*Server, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	s := &Server{
		config:    cfg,
		engine:    eng,
		logger:    logger,
		startTime: time.Now(),
		checks:    make(map[string]bool),
	}

	// Initialize audit logger if enabled
	if cfg.AuditEnabled {
		if err := s.initAuditLogger(); err != nil {
			return nil, fmt.Errorf("initializing audit logger: %w", err)
		}
	}

	return s, nil
}

// initAuditLogger initializes the audit log file.
func (s *Server) initAuditLogger() error {
	auditPath := s.config.AuditPath
	if auditPath == "" {
		auditPath = "/var/log/q/audit.log"
	}

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(auditPath), 0755); err != nil {
		return fmt.Errorf("creating audit log directory: %w", err)
	}

	// Open file for append
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}

	s.auditFile = f
	s.auditLogger = slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	s.logger.Info("audit logging enabled", zap.String("path", auditPath))
	return nil
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	// Load initial policies
	if s.config.PolicyDir != "" {
		if err := s.engine.LoadPoliciesFromDir(ctx, s.config.PolicyDir); err != nil {
			s.logger.Warn("failed to load policies from directory", zap.Error(err))
		}
	}

	errCh := make(chan error, 1)

	// Start HTTP server
	go func() {
		if err := s.startHTTP(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Mark as ready
	s.mu.Lock()
	s.ready = true
	s.checks["policies"] = true
	s.checks["http"] = true
	s.mu.Unlock()

	s.logger.Info("server started",
		zap.String("http", s.config.HTTPAddr),
	)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return s.Stop()
	}
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	s.logger.Info("shutting down server")

	// Close audit log file
	if s.auditFile != nil {
		s.auditFile.Close()
	}

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}

func (s *Server) startHTTP() error {
	mux := http.NewServeMux()

	s.logger.Info("registering HTTP handlers")

	// Health endpoints
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// Policy evaluation endpoints
	mux.HandleFunc("/v1/evaluate", s.handleEvaluate)
	mux.HandleFunc("/v1/validate", s.handleValidate)

	// Policy management endpoints
	mux.HandleFunc("/v1/policies", s.handlePolicies)
	mux.HandleFunc("/v1/policies/reload", s.handleReloadPolicies)

	s.httpServer = &http.Server{
		Addr:    s.config.HTTPAddr,
		Handler: corsMiddleware(mux),
	}

	s.logger.Info("starting HTTP server", zap.String("addr", s.config.HTTPAddr))
	return s.httpServer.ListenAndServe()
}

// HTTP Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	healthy := s.ready
	s.mu.RUnlock()

	resp := map[string]interface{}{
		"healthy": healthy,
		"version": "0.1.0",
		"uptime":  time.Since(s.startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.ready
	checks := s.checks
	s.mu.RUnlock()

	resp := map[string]interface{}{
		"ready":  ready,
		"checks": checks,
	}

	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.New().String()
	}

	var req struct {
		Input         map[string]interface{} `json:"input"`
		Namespace     string                 `json:"namespace"`
		Policies      []string               `json:"policies"`
		Trace         bool                   `json:"trace"`
		IncludePassed bool                   `json:"include_passed"`
		Strict        bool                   `json:"strict"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.Input == nil {
		http.Error(w, "input is required", http.StatusBadRequest)
		return
	}

	engineReq := &engine.EvaluateRequest{
		Input:     req.Input,
		Namespace: req.Namespace,
		Policies:  req.Policies,
		Options: engine.EvaluateOptions{
			Trace:         req.Trace,
			IncludePassed: req.IncludePassed,
			Strict:        req.Strict,
		},
	}

	result, err := s.engine.Evaluate(r.Context(), engineReq)
	if err != nil {
		s.logger.Error("evaluation failed", zap.Error(err))
		http.Error(w, fmt.Sprintf("Evaluation failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Count violations
	violations := 0
	for _, r := range result.Results {
		if !r.Passed {
			violations++
		}
	}

	// Write audit log
	if s.auditLogger != nil {
		s.auditLogger.Info("decision",
			"request_id", requestID,
			"timestamp", time.Now().UTC().Format(time.RFC3339Nano),
			"decision", decisionToString(result.Decision),
			"namespace", req.Namespace,
			"policies_evaluated", result.Metrics.PoliciesEvaluated,
			"rules_evaluated", result.Metrics.RulesEvaluated,
			"violations", violations,
			"duration_ms", time.Since(startTime).Milliseconds(),
			"source_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"input_kind", req.Input["kind"],
			"input_name", getNestedString(req.Input, "metadata", "name"),
		)
	}

	// Convert to HTTP response
	resp := map[string]interface{}{
		"decision":   decisionToString(result.Decision),
		"request_id": requestID,
		"results":    make([]map[string]interface{}, len(result.Results)),
	}

	for i, r := range result.Results {
		resp["results"].([]map[string]interface{})[i] = map[string]interface{}{
			"policy_name":      r.PolicyName,
			"policy_namespace": r.PolicyNamespace,
			"rule_id":          r.RuleID,
			"description":      r.RuleDescription,
			"severity":         severityToString(r.Severity),
			"passed":           r.Passed,
			"message":          r.Message,
		}
	}

	if result.Metrics != nil {
		resp["metrics"] = map[string]interface{}{
			"evaluation_time_ns": result.Metrics.EvaluationTimeNs,
			"policies_evaluated": result.Metrics.PoliciesEvaluated,
			"rules_evaluated":    result.Metrics.RulesEvaluated,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", requestID)
	json.NewEncoder(w).Encode(resp)
}

// getNestedString safely extracts a nested string value.
func getNestedString(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key]; ok {
				if s, ok := val.(string); ok {
					return s
				}
			}
			return ""
		}
		if next, ok := current[key]; ok {
			if nextMap, ok := next.(map[string]interface{}); ok {
				current = nextMap
			} else {
				return ""
			}
		} else {
			return ""
		}
	}
	return ""
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Policy   string `json:"policy"`
		Filename string `json:"filename"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	errors, warnings := s.engine.Validate(req.Policy)

	resp := map[string]interface{}{
		"valid":    len(errors) == 0,
		"errors":   errors,
		"warnings": warnings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		namespace := r.URL.Query().Get("namespace")
		policies := s.engine.ListPolicies(namespace)

		// Convert to serializable format
		policyList := make([]map[string]interface{}, len(policies))
		for i, p := range policies {
			policyList[i] = map[string]interface{}{
				"name":       p.Name,
				"namespace":  p.Namespace,
				"rule_count": len(p.Rules),
			}
		}

		resp := map[string]interface{}{
			"policies": policyList,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		namespace := r.URL.Query().Get("namespace")

		deleted := s.engine.DeletePolicy(namespace, name)

		resp := map[string]interface{}{
			"deleted": deleted,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleReloadPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.config.PolicyDir == "" {
		http.Error(w, "No policy directory configured", http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	// Use atomic reload - safe during concurrent evaluations
	count, err := s.engine.ReloadPoliciesFromDir(r.Context(), s.config.PolicyDir)
	if err != nil {
		s.logger.Error("policy reload failed", zap.Error(err))
		resp := map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	s.logger.Info("policies reloaded",
		zap.Int("count", count),
		zap.Duration("duration", time.Since(startTime)),
	)

	resp := map[string]interface{}{
		"success":         true,
		"policies_loaded": count,
		"reload_time_ms":  time.Since(startTime).Milliseconds(),
		"policy_dir":      s.config.PolicyDir,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Helper functions

func decisionToString(d engine.Decision) string {
	switch d {
	case engine.DecisionAllow:
		return "allow"
	case engine.DecisionDeny:
		return "deny"
	case engine.DecisionWarn:
		return "warn"
	default:
		return "unknown"
	}
}

func severityToString(s engine.Severity) string {
	switch s {
	case engine.SeverityCritical:
		return "critical"
	case engine.SeverityHigh:
		return "high"
	case engine.SeverityMedium:
		return "medium"
	case engine.SeverityLow:
		return "low"
	case engine.SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// CORS middleware
func corsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-Id")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}
