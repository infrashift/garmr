// internal/health/handler.go
// Package health provides health check endpoints for Kubernetes probes.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// Check represents a single health check.
type Check struct {
	Name    string        `json:"name"`
	Status  Status        `json:"status"`
	Message string        `json:"message,omitempty"`
	Latency time.Duration `json:"latency,omitempty"`
}

// Response is the health check response.
type Response struct {
	Status    Status            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Version   string            `json:"version,omitempty"`
	Checks    map[string]*Check `json:"checks,omitempty"`
}

// Checker is a function that performs a health check.
type Checker func(ctx context.Context) *Check

// Handler manages health checks and serves health endpoints.
type Handler struct {
	mu sync.RWMutex
	// checkers run on readiness probes and must stay cheap.
	checkers map[string]Checker
	// deepCheckers run only on /health/deep — anything that talks to a
	// network dependency belongs here.
	deepCheckers map[string]Checker
	version      string
}

// NewHandler creates a new health handler.
func NewHandler(version string) *Handler {
	return &Handler{
		checkers:     make(map[string]Checker),
		deepCheckers: make(map[string]Checker),
		version:      version,
	}
}

// Register registers a health checker that runs on readiness probes.
//
// Readiness is polled by the kubelet every few seconds, so only cheap,
// in-process checks belong here. Anything that talks to a network dependency
// should use RegisterDeep.
func (h *Handler) Register(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[name] = checker
}

// RegisterDeep registers a health checker that runs only on /health/deep.
//
// Use this for checks with a real cost — a round trip to a storage backend,
// for example. Registering those as readiness checks turns every kubelet
// probe into external traffic.
func (h *Handler) RegisterDeep(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deepCheckers[name] = checker
}

// Check runs every registered health check, readiness and deep alike.
// /health/deep and external callers use this; readiness uses checkReadiness.
func (h *Handler) Check(ctx context.Context) *Response {
	return h.runCheckers(ctx, true)
}

// checkReadiness runs only the cheap readiness checkers.
func (h *Handler) checkReadiness(ctx context.Context) *Response {
	return h.runCheckers(ctx, false)
}

func (h *Handler) runCheckers(ctx context.Context, includeDeep bool) *Response {
	h.mu.RLock()
	checkers := make(map[string]Checker, len(h.checkers))
	for k, v := range h.checkers {
		checkers[k] = v
	}
	if includeDeep {
		for k, v := range h.deepCheckers {
			checkers[k] = v
		}
	}
	h.mu.RUnlock()

	resp := &Response{
		Status:    StatusHealthy,
		Timestamp: time.Now().UTC(),
		Version:   h.version,
		Checks:    make(map[string]*Check, len(checkers)),
	}

	// Run checks in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker Checker) {
			defer wg.Done()

			start := time.Now()
			check := runChecker(ctx, name, checker)
			check.Name = name
			check.Latency = time.Since(start)

			mu.Lock()
			resp.Checks[name] = check

			// Update overall status
			if check.Status == StatusUnhealthy {
				resp.Status = StatusUnhealthy
			} else if check.Status == StatusDegraded && resp.Status == StatusHealthy {
				resp.Status = StatusDegraded
			}
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()
	return resp
}

// runChecker invokes one checker, converting a panic or a nil result into an
// unhealthy check.
//
// Checkers run on their own goroutines, so the server's recovery middleware —
// which only wraps the request goroutine — cannot catch a panic here: one
// misbehaving checker took the whole process down instead of reporting 503.
// A checker that returns nil did the same via a nil dereference.
func runChecker(ctx context.Context, name string, checker Checker) (check *Check) {
	defer func() {
		if r := recover(); r != nil {
			check = &Check{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("check panicked: %v", r),
			}
		}
	}()

	if check = checker(ctx); check == nil {
		check = &Check{
			Status:  StatusUnhealthy,
			Message: "check returned no result",
		}
	}
	return check
}

// LivenessHandler returns the liveness probe handler.
//
// Liveness means "the process is serving HTTP" and is deliberately constant:
// failing it restarts the process, which fixes none of the failure modes the
// checkers detect (a bad policy set or an unreachable backend survives a
// restart). Those belong to readiness, which takes the instance out of
// rotation instead.
func (h *Handler) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := &Response{
			Status:    StatusHealthy,
			Timestamp: time.Now().UTC(),
			Version:   h.version,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ReadinessHandler returns the readiness probe handler.
// This checks if Garmr is ready to accept traffic.
func (h *Handler) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Readiness checks only — deep checkers (e.g. a storage round trip)
		// are excluded so a kubelet probe does not generate external traffic
		// every few seconds.
		resp := h.checkReadiness(ctx)

		// Headers must be set before WriteHeader or they are dropped
		w.Header().Set("Content-Type", "application/json")
		if resp.Status == StatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		_ = json.NewEncoder(w).Encode(resp)
	}
}

// DeepHealthHandler returns a comprehensive health check, running the deep
// checkers (storage round trip) alongside the cheap ones. It is for
// operators and monitoring, not for probes — but the status code is still
// honest: 200 only when every check is healthy, 503 otherwise, so `curl -f`
// and alerting rules work without parsing the body. Per-check detail stays
// in the body.
func (h *Handler) DeepHealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		resp := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")
		if resp.Status == StatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// RegisterRoutes registers health endpoints on a mux.
//
// /healthz and /livez both serve the cheap cached liveness check — kubelet
// probes hit these every few seconds, so they must never fan out to storage
// backends. The comprehensive check (which runs every registered checker,
// including storage) is served at /health/deep for debugging and monitoring.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.LivenessHandler())
	mux.HandleFunc("/livez", h.LivenessHandler())
	mux.HandleFunc("/readyz", h.ReadinessHandler())
	mux.HandleFunc("/health/deep", h.DeepHealthHandler())
}
