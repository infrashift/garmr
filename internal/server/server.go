// internal/server/server.go
// Package server provides the HTTP server implementation.
package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/experimental/ratelimit"
	"github.com/infrashift/garmr/internal/health"
	"github.com/infrashift/garmr/internal/input"
	"github.com/infrashift/garmr/internal/observability"
)

//go:embed openapi.json
var openAPISpec []byte

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
	// Authentication
	APIKey          string   // Required API key (empty = no auth)
	APIKeyHeader    string   // Header name for API key (default: X-API-Key)
	AuthExemptPaths []string // Paths exempt from auth (e.g., /health, /ready)
	// CORS
	CORSAllowedOrigins []string // Allowed origins (empty = allow all for dev)
	// Rate limiting
	RateLimitEnabled   bool
	RateLimitPerSecond float64
	RateLimitBurst     int
}

// Server is the Garmr server.
type Server struct {
	config        Config
	engine        *engine.Engine
	logger        *zap.Logger
	httpServer    *http.Server
	startTime     time.Time
	auditLogger   *slog.Logger
	auditFile     *os.File
	rateLimiter   *ratelimit.Limiter
	healthHandler *health.Handler
	obs           *observability.Provider

	mu     sync.RWMutex
	ready  bool
	checks map[string]bool
}

// NewServer creates a new server instance.
func NewServer(cfg Config, eng *engine.Engine, logger *zap.Logger) (*Server, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	obs := observability.NewProvider()

	s := &Server{
		config:    cfg,
		engine:    eng,
		logger:    logger,
		startTime: time.Now(),
		checks:    make(map[string]bool),
		obs:       obs,
	}

	// Wire observability into the engine
	eng.SetObservability(obs)

	// Initialize audit logger if enabled
	if cfg.AuditEnabled {
		if err := s.initAuditLogger(); err != nil {
			return nil, fmt.Errorf("initializing audit logger: %w", err)
		}
	}

	// Initialize rate limiter if enabled
	if cfg.RateLimitEnabled {
		rlConfig := ratelimit.DefaultConfig()
		if cfg.RateLimitPerSecond > 0 {
			rlConfig.RequestsPerSecond = cfg.RateLimitPerSecond
		}
		if cfg.RateLimitBurst > 0 {
			rlConfig.Burst = cfg.RateLimitBurst
		}
		s.rateLimiter = ratelimit.New(rlConfig)
	}

	// Initialize health handler
	s.healthHandler = health.NewHandler("0.1.0")

	// Register a policy loader health checker
	s.healthHandler.Register("policies", func(ctx context.Context) *health.Check {
		policies := eng.ListPolicies("")
		if len(policies) == 0 {
			return &health.Check{
				Status:  health.StatusDegraded,
				Message: "no policies loaded",
			}
		}
		return &health.Check{
			Status:  health.StatusHealthy,
			Message: fmt.Sprintf("%d policies loaded", len(policies)),
		}
	})

	return s, nil
}

// initAuditLogger initializes the audit log file.
func (s *Server) initAuditLogger() error {
	auditPath := s.config.AuditPath
	if auditPath == "" {
		auditPath = "/var/log/garmr/audit.log"
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

	// Close rate limiter
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
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

	// Health endpoints - use sophisticated health handler
	s.healthHandler.RegisterRoutes(mux)
	// Keep legacy endpoints for backwards compatibility
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// Policy evaluation endpoints
	mux.HandleFunc("/v1/evaluate", s.handleEvaluate)
	mux.HandleFunc("/v1/validate", s.handleValidate)

	// Policy management endpoints
	mux.HandleFunc("/v1/policies", s.handlePolicies)
	mux.HandleFunc("/v1/policies/reload", s.handleReloadPolicies)

	// Metrics endpoint
	mux.HandleFunc("/metrics", s.handleMetrics)

	// OpenAPI / Swagger endpoints
	mux.HandleFunc("/openapi.json", s.handleOpenAPI)
	mux.HandleFunc("/swagger-ui", s.handleSwaggerUI)
	mux.HandleFunc("/swagger-ui/", s.handleSwaggerUI)

	// Build middleware chain
	var handler http.Handler = corsMiddleware(mux, s.config.CORSAllowedOrigins)
	if s.rateLimiter != nil {
		handler = s.rateLimiter.Middleware(handler)
	}
	handler = s.authMiddleware(handler)

	s.httpServer = &http.Server{
		Addr:         s.config.HTTPAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if s.config.EnableTLS {
		s.logger.Info("starting HTTPS server", zap.String("addr", s.config.HTTPAddr))
		return s.httpServer.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
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

	// Read request body with size limit
	maxSize := int64(s.config.MaxRecvSize)
	if maxSize <= 0 {
		maxSize = 1 << 20 // 1MB default
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	// Detect input format from Content-Type header
	parser := input.NewParser()
	contentType := r.Header.Get("Content-Type")
	format := parser.DetectFormatFromContentType(contentType)

	// Parse the request body based on format
	var req struct {
		Input         map[string]interface{} `json:"input" yaml:"input"`
		Namespace     string                 `json:"namespace" yaml:"namespace"`
		Policies      []string               `json:"policies" yaml:"policies"`
		Trace         bool                   `json:"trace" yaml:"trace"`
		IncludePassed bool                   `json:"include_passed" yaml:"include_passed"`
		Strict        bool                   `json:"strict" yaml:"strict"`
	}

	// Parse based on detected format
	parsed, err := parser.Parse(body, format)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Map parsed data to request struct
	if inputData, ok := parsed["input"].(map[string]interface{}); ok {
		req.Input = inputData
	}
	if ns, ok := parsed["namespace"].(string); ok {
		req.Namespace = ns
	}
	if policies, ok := parsed["policies"].([]interface{}); ok {
		for _, p := range policies {
			if ps, ok := p.(string); ok {
				req.Policies = append(req.Policies, ps)
			}
		}
	}
	if trace, ok := parsed["trace"].(bool); ok {
		req.Trace = trace
	}
	if includePassed, ok := parsed["include_passed"].(bool); ok {
		req.IncludePassed = includePassed
	}
	if strict, ok := parsed["strict"].(bool); ok {
		req.Strict = strict
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

	// Record HTTP evaluation metrics
	s.obs.Metrics().RecordEvaluation(
		"",
		req.Namespace,
		decisionToString(result.Decision),
		"",
		time.Since(startTime),
	)

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

	// Apply request body size limit
	maxSize := int64(s.config.MaxRecvSize)
	if maxSize <= 0 {
		maxSize = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

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

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Placeholder for Prometheus metrics endpoint
	// Will be populated when metrics plugin is loaded
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("# Garmr metrics endpoint\n# Load prometheus plugin for full metrics\n"))
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

// handleOpenAPI serves the OpenAPI specification
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(openAPISpec)
}

// handleSwaggerUI serves a simple Swagger UI page
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(swaggerUIHTML))
}

// Swagger UI HTML (uses CDN)
var swaggerUIHTML = `<!DOCTYPE html>
<html>
<head>
  <title>Garmr - API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/openapi.json",
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`

// CORS middleware
func corsMiddleware(h http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if len(allowedOrigins) == 0 {
			// No restrictions configured (dev mode)
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			// Check if the origin is allowed
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-Id, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// authMiddleware provides API key authentication.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if no API key configured
		if s.config.APIKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check exempt paths
		for _, path := range s.config.AuthExemptPaths {
			if r.URL.Path == path {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Always exempt health/ready endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/livez" {
			next.ServeHTTP(w, r)
			return
		}

		// Check API key
		headerName := s.config.APIKeyHeader
		if headerName == "" {
			headerName = "X-API-Key"
		}

		providedKey := r.Header.Get(headerName)
		if providedKey == "" {
			// Also check Authorization: Bearer
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				providedKey = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if providedKey != s.config.APIKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid or missing API key",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
