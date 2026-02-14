// internal/health/handler.go
// Package health provides health check endpoints for Kubernetes probes.
package health

import (
	"context"
	"encoding/json"
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
	mu       sync.RWMutex
	checkers map[string]Checker
	version  string

	// Cached status for liveness (avoids expensive checks)
	liveStatus Status
}

// NewHandler creates a new health handler.
func NewHandler(version string) *Handler {
	return &Handler{
		checkers:   make(map[string]Checker),
		version:    version,
		liveStatus: StatusHealthy,
	}
}

// Register registers a health checker.
func (h *Handler) Register(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[name] = checker
}

// Unregister removes a health checker.
func (h *Handler) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checkers, name)
}

// SetLive sets the liveness status.
func (h *Handler) SetLive(live bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if live {
		h.liveStatus = StatusHealthy
	} else {
		h.liveStatus = StatusUnhealthy
	}
}

// Check runs all health checks.
func (h *Handler) Check(ctx context.Context) *Response {
	h.mu.RLock()
	checkers := make(map[string]Checker, len(h.checkers))
	for k, v := range h.checkers {
		checkers[k] = v
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
			check := checker(ctx)
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

// LivenessHandler returns the liveness probe handler.
// This is a simple check that Garmr is running.
func (h *Handler) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		status := h.liveStatus
		h.mu.RUnlock()

		resp := &Response{
			Status:    status,
			Timestamp: time.Now().UTC(),
			Version:   h.version,
		}

		if status == StatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ReadinessHandler returns the readiness probe handler.
// This checks if Garmr is ready to accept traffic.
func (h *Handler) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		resp := h.Check(ctx)

		if resp.Status == StatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// DeepHealthHandler returns a comprehensive health check.
// This is for debugging and monitoring, not for probes.
func (h *Handler) DeepHealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		resp := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // Always 200 for deep health
		json.NewEncoder(w).Encode(resp)
	}
}

// RegisterRoutes registers health endpoints on a mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.LivenessHandler())
	mux.HandleFunc("/readyz", h.ReadinessHandler())
	mux.HandleFunc("/livez", h.DeepHealthHandler())
}

// Common health checkers

// PolicyLoaderChecker creates a checker for policy loader health.
func PolicyLoaderChecker(loader interface{ Health() error }) Checker {
	return func(ctx context.Context) *Check {
		if err := loader.Health(); err != nil {
			return &Check{
				Status:  StatusUnhealthy,
				Message: err.Error(),
			}
		}
		return &Check{Status: StatusHealthy}
	}
}

// StorageBackendChecker creates a checker for storage backend health.
func StorageBackendChecker(name string, backend interface{ Health(context.Context) error }) Checker {
	return func(ctx context.Context) *Check {
		if err := backend.Health(ctx); err != nil {
			return &Check{
				Status:  StatusUnhealthy,
				Message: err.Error(),
			}
		}
		return &Check{Status: StatusHealthy}
	}
}

// PluginChecker creates a checker for a plugin.
func PluginChecker(name string, plugin interface{ Health(context.Context) error }) Checker {
	return func(ctx context.Context) *Check {
		if err := plugin.Health(ctx); err != nil {
			return &Check{
				Status:  StatusUnhealthy,
				Message: err.Error(),
			}
		}
		return &Check{Status: StatusHealthy}
	}
}

// DiskSpaceChecker creates a checker for available disk space.
func DiskSpaceChecker(path string, minFreeBytes uint64) Checker {
	return func(ctx context.Context) *Check {
		// In production, use syscall.Statfs
		// This is a placeholder
		return &Check{
			Status:  StatusHealthy,
			Message: "disk space OK",
		}
	}
}

// MemoryChecker creates a checker for memory usage.
func MemoryChecker(maxUsagePercent float64) Checker {
	return func(ctx context.Context) *Check {
		// In production, use runtime.MemStats
		// This is a placeholder
		return &Check{
			Status:  StatusHealthy,
			Message: "memory OK",
		}
	}
}
