// internal/server/server.go
// Package server provides the HTTP server implementation.
package server

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/health"
	"github.com/infrashift/garmr/internal/input"
	"github.com/infrashift/garmr/internal/observability"
	"github.com/infrashift/garmr/internal/ratelimit"
	"github.com/infrashift/garmr/internal/storage"
)

//go:embed openapi.json
var openAPISpec []byte

// Config holds server configuration.
type Config struct {
	HTTPAddr        string
	PolicyDir       string
	TLSCert         string
	TLSKey          string
	EnableTLS       bool
	MaxRecvSize     int
	ShutdownTimeout time.Duration // graceful shutdown timeout (default 30s)
	Version         string        // reported in /health and the health handler; injected via ldflags in main
	// Audit logging
	AuditEnabled    bool
	AuditPath       string
	AuditMaxSizeMB  int // Max size in MB before rotation (default 100)
	AuditMaxBackups int // Max number of old log files (default 10)
	AuditMaxAgeDays int // Max age in days for old log files (default 30)
	// Authentication
	APIKey          string   // Required API key (empty = no auth)
	APIKeyHeader    string   // Header name for API key (default: X-API-Key)
	AuthExemptPaths []string // Paths exempt from auth (e.g., /health, /ready)
	// Mesh-provided caller identity
	IdentityHeader string // Header carrying mesh-verified client identity (default: X-Forwarded-Client-Cert)
	// CORS
	CORSAllowedOrigins []string // Allowed origins (empty = allow all for dev)
	// Rate limiting
	RateLimitEnabled   bool
	RateLimitPerSecond float64
	RateLimitBurst     int
	// RateLimitTrustedProxies lists CIDRs whose X-Forwarded-For header is
	// believed for per-client identification. Empty means never trust it.
	RateLimitTrustedProxies []string
	// Storage backend
	StorageType    string                 // "filesystem" (default)
	StorageRoot    string                 // Root path/prefix for storage backend
	StorageOptions map[string]interface{} // Backend-specific options
	// Evaluation posture
	// RequireMatch is a tri-state: nil means "use the engine default" (true /
	// fail-closed). A non-nil pointer lets operators explicitly opt out via
	// config. Pointer form is used because the bool zero value cannot be
	// distinguished from "unset" when Config is populated field-by-field.
	RequireMatch *bool
}

// Server is the Garmr server.
type Server struct {
	config         Config
	engine         *engine.Engine
	logger         *zap.Logger
	httpServer     *http.Server
	startTime      time.Time
	auditLogger    *slog.Logger
	auditFile      io.Closer
	rateLimiter    *ratelimit.Limiter
	healthHandler  *health.Handler
	obs            *observability.Provider
	storageBackend storage.Backend

	mu       sync.RWMutex
	ready    bool
	checks   map[string]bool
	stopOnce sync.Once
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

	// Apply evaluation posture. When unset, leave the engine's default
	// (true / fail-closed) in place.
	if cfg.RequireMatch != nil {
		eng.SetRequireMatch(*cfg.RequireMatch)
	}

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
		rlConfig.TrustedProxies = cfg.RateLimitTrustedProxies
		s.rateLimiter = ratelimit.New(rlConfig)
		// Without this the limiter is unobservable: the collector was
		// registered but garmr_rate_limit_hits_total was never incremented.
		s.rateLimiter.SetOnLimited(func() {
			s.obs.Metrics().RecordRateLimitHit("")
		})
	}

	// Initialize health handler
	version := cfg.Version
	if version == "" {
		version = "dev"
	}
	s.healthHandler = health.NewHandler(version)

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

	// Storage is a DEEP checker: it makes a real round trip to the backend.
	// Registered as a readiness check it ran on every kubelet probe, and the
	// Helm chart points readinessProbe at /readyz.
	s.healthHandler.RegisterDeep("storage", func(ctx context.Context) *health.Check {
		if s.storageBackend == nil {
			return &health.Check{
				Status:  health.StatusHealthy,
				Message: "no storage backend configured",
			}
		}
		// Try listing files as a basic health check
		_, err := s.storageBackend.List(ctx, "**/*.cue")
		if err != nil {
			return &health.Check{
				Status:  health.StatusUnhealthy,
				Message: fmt.Sprintf("storage backend error: %v", err),
			}
		}
		return &health.Check{
			Status:  health.StatusHealthy,
			Message: fmt.Sprintf("storage backend %s operational", s.storageBackend.Type()),
		}
	})

	// A misconfigured backend must fail startup: silently running with zero
	// policies would deny everything under require_match (or worse, allow
	// everything without it).
	if err := s.initStorageBackend(); err != nil {
		return nil, fmt.Errorf("initializing storage backend: %w", err)
	}

	return s, nil
}

// initAuditLogger initializes the audit log with rotation via lumberjack.
func (s *Server) initAuditLogger() error {
	auditPath := s.config.AuditPath
	if auditPath == "" {
		auditPath = "/var/log/garmr/audit.log"
	}

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(auditPath), 0755); err != nil {
		return fmt.Errorf("creating audit log directory: %w", err)
	}

	maxSize := s.config.AuditMaxSizeMB
	if maxSize <= 0 {
		maxSize = 100
	}
	maxBackups := s.config.AuditMaxBackups
	if maxBackups <= 0 {
		maxBackups = 10
	}
	maxAge := s.config.AuditMaxAgeDays
	if maxAge <= 0 {
		maxAge = 30
	}

	lj := &lumberjack.Logger{
		Filename:   auditPath,
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   true,
	}

	s.auditFile = lj
	s.auditLogger = slog.New(slog.NewJSONHandler(lj, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	s.logger.Info("audit logging enabled",
		zap.String("path", auditPath),
		zap.Int("max_size_mb", maxSize),
		zap.Int("max_backups", maxBackups),
		zap.Int("max_age_days", maxAge),
	)
	return nil
}

// initStorageBackend initializes the storage backend based on configuration.
// If StorageType is empty and PolicyDir is set, creates a FilesystemBackend.
// If StorageType is set, uses the storage registry to create the appropriate backend.
func (s *Server) initStorageBackend() error {
	if s.config.StorageType == "" && s.config.PolicyDir == "" {
		return nil // No storage configured
	}

	if s.config.StorageType == "" {
		// Backward compat: --policy-dir maps to filesystem backend
		cfg := storage.Config{
			Type: "filesystem",
			Root: s.config.PolicyDir,
		}
		backend, err := storage.New(cfg)
		if err != nil {
			return fmt.Errorf("creating filesystem backend: %w", err)
		}
		s.storageBackend = backend
		s.logger.Info("storage backend initialized",
			zap.String("type", "filesystem"),
			zap.String("root", s.config.PolicyDir),
		)
		return nil
	}

	// Build storage config from StorageType + StorageOptions
	cfg := storage.Config{
		Type:    s.config.StorageType,
		Root:    s.config.StorageRoot,
		Options: s.config.StorageOptions,
	}

	backend, err := storage.New(cfg)
	if err != nil {
		return fmt.Errorf("creating %s backend: %w", s.config.StorageType, err)
	}
	s.storageBackend = backend
	s.logger.Info("storage backend initialized",
		zap.String("type", s.config.StorageType),
		zap.String("root", s.config.StorageRoot),
	)
	return nil
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	// Load policies from the storage backend wired up in NewServer.
	//
	// This fails startup rather than warning. NewServer already documents
	// that a misconfigured backend must not start; warning here contradicted
	// that and left the process serving with zero policies, which under
	// require_match denies everything (and without it allows everything).
	if s.storageBackend != nil {
		if err := s.engine.LoadPoliciesFromBackend(ctx, s.storageBackend); err != nil {
			return fmt.Errorf("loading policies from storage backend: %w", err)
		}
	}

	errCh := make(chan error, 1)

	// Build the server synchronously so s.httpServer is set before anything
	// can observe it, then serve on a goroutine.
	srv := s.newHTTPServer()
	go func() {
		if err := s.serve(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Mark as ready. The policies check reflects reality rather than being
	// hardcoded true — otherwise legacy /ready reported 200 with zero
	// policies loaded while /readyz reported 503, so the two probes
	// contradicted each other.
	s.mu.Lock()
	s.ready = true
	s.checks["policies"] = len(s.engine.ListPolicies("")) > 0
	s.checks["http"] = true
	s.mu.Unlock()

	s.logger.Info("server started",
		zap.String("http", s.config.HTTPAddr),
	)

	select {
	case err := <-errCh:
		// Stop() too, or the audit file, storage backend and rate-limiter
		// goroutine leak whenever the listener fails.
		return errors.Join(err, s.Stop())
	case <-ctx.Done():
		return s.Stop()
	}
}

// Stop gracefully shuts down the server.
//
// Ordering is load-bearing: in-flight requests are drained BEFORE the
// dependencies they need are closed. Closing the storage backend, audit sink
// and rate limiter first (as this used to) meant a reload in flight hit a
// closed backend, and decisions completing during the drain window lost their
// audit records.
//
// Safe to call more than once — Start calls it on both the ctx.Done() and the
// serve-error paths.
func (s *Server) Stop() error {
	var err error

	s.stopOnce.Do(func() {
		s.logger.Info("shutting down server")

		// Fail probes first so a load balancer stops sending new work while
		// the drain runs.
		s.mu.Lock()
		s.ready = false
		s.checks["http"] = false
		srv := s.httpServer
		s.mu.Unlock()

		var errs []error

		// 1. Drain in-flight requests.
		if srv != nil {
			timeout := s.config.ShutdownTimeout
			if timeout <= 0 {
				timeout = 30 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if shutErr := srv.Shutdown(ctx); shutErr != nil {
				errs = append(errs, fmt.Errorf("draining HTTP server: %w", shutErr))
			}
		}

		// 2. Only then release what those requests depended on.
		if s.rateLimiter != nil {
			s.rateLimiter.Close()
		}
		if s.auditFile != nil {
			if closeErr := s.auditFile.Close(); closeErr != nil {
				errs = append(errs, fmt.Errorf("closing audit log: %w", closeErr))
			}
		}
		if s.storageBackend != nil {
			if closeErr := s.storageBackend.Close(); closeErr != nil {
				errs = append(errs, fmt.Errorf("closing storage backend: %w", closeErr))
			}
		}

		err = errors.Join(errs...)
	})

	return err
}

// Handler returns the fully-wired HTTP handler (routes + middleware).
// Intended for tests that want to drive the server via httptest without binding a port.
func (s *Server) Handler() http.Handler {
	return s.buildHandler()
}

// Observability returns the observability provider, allowing callers to
// register metrics recorders, tracers, or audit loggers after construction.
func (s *Server) Observability() *observability.Provider {
	return s.obs
}

// MarkReady flips the server into a ready state for tests that use Handler()
// in place of Start(). Production code paths call Start(), which sets the
// same flags internally.
func (s *Server) MarkReady() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = true
	if s.checks == nil {
		s.checks = make(map[string]bool)
	}
	s.checks["policies"] = true
	s.checks["http"] = true
}

func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()

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

	// Middleware chain, innermost first. Reading outward the request passes
	// through: otel -> recovery -> CORS -> rate limit -> auth -> identity -> mux.
	//
	// Order matters twice here:
	//   - CORS must be OUTSIDE auth. Preflight OPTIONS requests carry no
	//     X-API-Key, so with auth outermost every preflight was answered 401
	//     with no CORS headers whenever an API key was configured — browsers
	//     could not call the API at all.
	//   - Rate limiting must also be outside auth, or unauthenticated floods
	//     are rejected by auth before the limiter ever sees them, which is
	//     exactly the traffic worth limiting.
	// Recovery stays outside both so panics in them still return a 500.
	var handler http.Handler = s.identityMiddleware(mux)
	handler = s.authMiddleware(handler)
	if s.rateLimiter != nil {
		handler = s.rateLimiter.Middleware(handler)
	}
	handler = corsMiddleware(handler, s.config.CORSAllowedOrigins)
	handler = s.recoveryMiddleware(handler)
	// otelhttp extracts `traceparent` from the incoming request and starts
	// a server span covering the whole middleware chain.
	handler = otelhttp.NewHandler(handler, "garmr-server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
	return handler
}

// newHTTPServer builds the *http.Server and stores it on s.
//
// Split from serve() so the assignment happens synchronously in Start rather
// than inside the serving goroutine: Stop() reads s.httpServer, so assigning
// it from the goroutine was a race.
func (s *Server) newHTTPServer() *http.Server {
	s.logger.Info("registering HTTP handlers")

	srv := &http.Server{
		Addr:         s.config.HTTPAddr,
		Handler:      s.buildHandler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.mu.Lock()
	s.httpServer = srv
	s.mu.Unlock()

	return srv
}

// serve blocks serving on srv. Only ever called from the Start goroutine.
func (s *Server) serve(srv *http.Server) error {
	if s.config.EnableTLS {
		s.logger.Info("starting HTTPS server", zap.String("addr", s.config.HTTPAddr))
		return srv.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}

	s.logger.Info("starting HTTP server", zap.String("addr", s.config.HTTPAddr))
	return srv.ListenAndServe()
}

// writeError writes a generic error message to the client and logs the full error server-side.
func (s *Server) writeError(w http.ResponseWriter, status int, userMsg string, err error) {
	if err != nil {
		s.logger.Error(userMsg, zap.Error(err))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": userMsg,
	})
}

// HTTP Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	healthy := s.ready
	s.mu.RUnlock()

	version := s.config.Version
	if version == "" {
		version = "dev"
	}
	resp := map[string]interface{}{
		"healthy": healthy,
		"version": version,
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
	// Clone: copying the map reference and encoding it after releasing the
	// lock races with Start/MarkReady/Stop writing the same map, which is an
	// unrecoverable "concurrent map read and map write" fatal error that
	// recoveryMiddleware cannot catch.
	checks := maps.Clone(s.checks)
	s.mu.RUnlock()

	// A failing check means not ready. Reporting 200 while a check is false
	// made this endpoint disagree with /readyz, which runs the same checks
	// properly.
	for _, ok := range checks {
		if !ok {
			ready = false
			break
		}
	}

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
		s.writeError(w, http.StatusBadRequest, "Failed to read request body", err)
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
		IncludePassed bool                   `json:"include_passed" yaml:"include_passed"`
	}

	// Parse based on detected format
	parsed, err := parser.Parse(body, format)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body", err)
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
	if includePassed, ok := parsed["include_passed"].(bool); ok {
		req.IncludePassed = includePassed
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
			IncludePassed: req.IncludePassed,
		},
	}

	result, err := s.engine.Evaluate(r.Context(), engineReq)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Evaluation failed", err)
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
			"principal", PrincipalFromContext(r.Context()),
			"trace_id", observability.TraceIDFromContext(r.Context()),
			"user_agent", r.UserAgent(),
			"input_kind", req.Input["kind"],
			"input_name", getNestedString(req.Input, "metadata", "name"),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", requestID)
	json.NewEncoder(w).Encode(evaluateResponseBody(result, requestID))
}

// evaluateResponseBody converts an engine response into the JSON body shape.
//
// Kept pure and separate from the handler so it can be unit-tested directly.
// It also carries the fields the engine has always computed but the API never
// returned: summary, evaluation_mode, terminated_early and termination_rule,
// which `garmr eval --help` promises.
func evaluateResponseBody(result *engine.EvaluateResponse, requestID string) map[string]interface{} {
	results := make([]map[string]interface{}, len(result.Results))
	for i, r := range result.Results {
		results[i] = map[string]interface{}{
			"policy_name":      r.PolicyName,
			"policy_namespace": r.PolicyNamespace,
			"rule_id":          r.RuleID,
			"description":      r.RuleDescription,
			"severity":         severityToString(r.Severity),
			"passed":           r.Passed,
			"message":          r.Message,
			"remediation":      r.Remediation,
		}
	}

	resp := map[string]interface{}{
		"decision":   decisionToString(result.Decision),
		"request_id": requestID,
		"results":    results,
		"summary": map[string]interface{}{
			"total_rules": result.Summary.TotalRules,
			"passed":      result.Summary.Passed,
			"failed":      result.Summary.Failed,
			"skipped":     result.Summary.Skipped,
		},
		"evaluation_mode": map[string]interface{}{
			"dry_run":              result.EvaluationMode.DryRun,
			"fail_fast":            result.EvaluationMode.FailFast,
			"short_circuited":      result.EvaluationMode.ShortCircuited,
			"total_rules_in_scope": result.EvaluationMode.TotalRulesInScope,
			"rules_evaluated":      result.EvaluationMode.RulesEvaluated,
			"rules_skipped":        result.EvaluationMode.RulesSkipped,
		},
		"terminated_early": result.TerminatedEarly,
	}

	if result.TerminationRule != nil {
		tr := result.TerminationRule
		resp["termination_rule"] = map[string]interface{}{
			"policy_name":      tr.PolicyName,
			"policy_namespace": tr.PolicyNamespace,
			"rule_id":          tr.RuleID,
			"description":      tr.RuleDescription,
			"severity":         severityToString(tr.Severity),
			"message":          tr.Message,
		}
	}

	if result.Metrics != nil {
		resp["metrics"] = map[string]interface{}{
			"evaluation_time_ns": result.Metrics.EvaluationTimeNs,
			"policies_evaluated": result.Metrics.PoliciesEvaluated,
			"rules_evaluated":    result.Metrics.RulesEvaluated,
		}
	}

	return resp
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

	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.New().String()
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
		s.writeError(w, http.StatusBadRequest, "Invalid JSON in request body", err)
		return
	}

	errors, warnings := s.engine.Validate(req.Policy)

	valid := len(errors) == 0

	// Audit log
	if s.auditLogger != nil {
		s.auditLogger.Info("validate",
			"request_id", requestID,
			"timestamp", time.Now().UTC().Format(time.RFC3339Nano),
			"valid", valid,
			"error_count", len(errors),
			"warning_count", len(warnings),
			"source_ip", r.RemoteAddr,
			"principal", PrincipalFromContext(r.Context()),
			"trace_id", observability.TraceIDFromContext(r.Context()),
		)
	}

	resp := map[string]interface{}{
		"valid":    valid,
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

		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		deleted := s.engine.DeletePolicy(namespace, name)

		// Audit log
		if s.auditLogger != nil {
			s.auditLogger.Info("policy_delete",
				"request_id", requestID,
				"timestamp", time.Now().UTC().Format(time.RFC3339Nano),
				"policy_name", name,
				"policy_namespace", namespace,
				"deleted", deleted,
				"source_ip", r.RemoteAddr,
				"principal", PrincipalFromContext(r.Context()),
				"trace_id", observability.TraceIDFromContext(r.Context()),
			)
		}

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

	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.New().String()
	}

	if s.storageBackend == nil {
		http.Error(w, "No policy source configured", http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	count, err := s.engine.ReloadPoliciesFromBackend(r.Context(), s.storageBackend)

	if err != nil {
		s.logger.Error("policy reload failed", zap.Error(err))

		// Audit log failure
		if s.auditLogger != nil {
			s.auditLogger.Info("policy_reload",
				"request_id", requestID,
				"timestamp", time.Now().UTC().Format(time.RFC3339Nano),
				"success", false,
				"error", err.Error(),
				"reload_time_ms", time.Since(startTime).Milliseconds(),
				"source_ip", r.RemoteAddr,
				"principal", PrincipalFromContext(r.Context()),
				"trace_id", observability.TraceIDFromContext(r.Context()),
			)
		}

		s.writeError(w, http.StatusInternalServerError, "Policy reload failed", err)
		return
	}

	s.logger.Info("policies reloaded",
		zap.Int("count", count),
		zap.Duration("duration", time.Since(startTime)),
	)

	// Audit log success
	if s.auditLogger != nil {
		s.auditLogger.Info("policy_reload",
			"request_id", requestID,
			"timestamp", time.Now().UTC().Format(time.RFC3339Nano),
			"success", true,
			"policies_loaded", count,
			"reload_time_ms", time.Since(startTime).Milliseconds(),
			"source_ip", r.RemoteAddr,
			"principal", PrincipalFromContext(r.Context()),
			"trace_id", observability.TraceIDFromContext(r.Context()),
		)
	}

	resp := map[string]interface{}{
		"success":         true,
		"policies_loaded": count,
		"reload_time_ms":  time.Since(startTime).Milliseconds(),
		"storage_type":    s.storageType(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if hh, ok := s.obs.Metrics().(interface{ Handler() http.Handler }); ok {
		hh.Handler().ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte("# Garmr metrics endpoint\n# No metrics recorder configured\n"))
}

// storageType returns the active storage type for API responses.
func (s *Server) storageType() string {
	if s.storageBackend != nil {
		return s.storageBackend.Type()
	}
	if s.config.PolicyDir != "" {
		return "filesystem"
	}
	return "none"
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

// recoveryMiddleware recovers from panics in downstream handlers,
// logs them with the request ID and stack trace, and returns a 500.
// Panics of http.ErrAbortHandler are re-raised per net/http convention.
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(rec)
			}

			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = "unknown"
			}

			var recErr error
			switch v := rec.(type) {
			case error:
				recErr = v
			default:
				recErr = fmt.Errorf("%v", v)
			}

			s.logger.Error("panic recovered in handler",
				zap.String("request_id", requestID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Error(recErr),
				zap.ByteString("stack", debug.Stack()),
			)

			if s.obs != nil {
				if inc, ok := s.obs.Metrics().(interface{ IncPanicsRecovered() }); ok {
					inc.IncPanicsRecovered()
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":      "internal server error",
				"request_id": requestID,
			})
		}()
		next.ServeHTTP(w, r)
	})
}

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

		if subtle.ConstantTimeCompare([]byte(providedKey), []byte(s.config.APIKey)) == 0 {
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
