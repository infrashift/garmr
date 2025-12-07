// internal/ratelimit/limiter.go
// Package ratelimit provides request rate limiting for Q Policy Agent.
package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config configures rate limiting.
type Config struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `json:"enabled"`

	// RequestsPerSecond is the global rate limit
	RequestsPerSecond float64 `json:"requestsPerSecond"`

	// Burst is the maximum burst size
	Burst int `json:"burst"`

	// PerClient enables per-client rate limiting
	PerClient bool `json:"perClient"`

	// ClientRequestsPerSecond is the per-client rate limit
	ClientRequestsPerSecond float64 `json:"clientRequestsPerSecond"`

	// ClientBurst is the per-client burst size
	ClientBurst int `json:"clientBurst"`

	// ClientIdentifier is how to identify clients: ip, header, cert
	ClientIdentifier string `json:"clientIdentifier"`

	// HeaderName for header-based client identification
	HeaderName string `json:"headerName"`

	// CleanupInterval for expired client limiters
	CleanupInterval time.Duration `json:"cleanupInterval"`

	// ClientTTL is how long to keep inactive client limiters
	ClientTTL time.Duration `json:"clientTtl"`

	// ExemptClients are client identifiers exempt from rate limiting
	ExemptClients []string `json:"exemptClients"`
}

// DefaultConfig returns a default rate limit configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:                 true,
		RequestsPerSecond:       10000,
		Burst:                   1000,
		PerClient:               true,
		ClientRequestsPerSecond: 1000,
		ClientBurst:             100,
		ClientIdentifier:        "ip",
		HeaderName:              "X-Client-ID",
		CleanupInterval:         time.Minute,
		ClientTTL:               10 * time.Minute,
	}
}

// Result represents the result of a rate limit check.
type Result struct {
	Allowed   bool          `json:"allowed"`
	Limit     float64       `json:"limit"`
	Remaining int           `json:"remaining"`
	Reset     time.Time     `json:"reset"`
	RetryIn   time.Duration `json:"retryIn,omitempty"`
}

// Limiter manages rate limiting.
type Limiter struct {
	config Config

	// Global limiter
	global *rate.Limiter

	// Per-client limiters
	clients   map[string]*clientLimiter
	clientsMu sync.RWMutex
	exemptSet map[string]bool

	// Cleanup
	stopCleanup chan struct{}
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New creates a new rate limiter.
func New(cfg Config) *Limiter {
	l := &Limiter{
		config:      cfg,
		clients:     make(map[string]*clientLimiter),
		exemptSet:   make(map[string]bool),
		stopCleanup: make(chan struct{}),
	}

	// Create global limiter
	l.global = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)

	// Build exempt set
	for _, client := range cfg.ExemptClients {
		l.exemptSet[client] = true
	}

	// Start cleanup goroutine
	if cfg.PerClient && cfg.CleanupInterval > 0 {
		go l.cleanup()
	}

	return l
}

// Allow checks if a request is allowed.
func (l *Limiter) Allow(clientID string) *Result {
	if !l.config.Enabled {
		return &Result{Allowed: true}
	}

	// Check exempt list
	if l.exemptSet[clientID] {
		return &Result{Allowed: true}
	}

	// Check global limit
	if !l.global.Allow() {
		return &Result{
			Allowed:   false,
			Limit:     l.config.RequestsPerSecond,
			Remaining: 0,
			RetryIn:   time.Second / time.Duration(l.config.RequestsPerSecond),
		}
	}

	// Check per-client limit
	if l.config.PerClient && clientID != "" {
		client := l.getOrCreateClient(clientID)
		if !client.limiter.Allow() {
			return &Result{
				Allowed:   false,
				Limit:     l.config.ClientRequestsPerSecond,
				Remaining: 0,
				RetryIn:   time.Second / time.Duration(l.config.ClientRequestsPerSecond),
			}
		}
	}

	return &Result{
		Allowed: true,
		Limit:   l.config.RequestsPerSecond,
	}
}

// AllowN checks if n requests are allowed.
func (l *Limiter) AllowN(clientID string, n int) *Result {
	if !l.config.Enabled {
		return &Result{Allowed: true}
	}

	if l.exemptSet[clientID] {
		return &Result{Allowed: true}
	}

	// Check global limit
	if !l.global.AllowN(time.Now(), n) {
		return &Result{
			Allowed:   false,
			Limit:     l.config.RequestsPerSecond,
			Remaining: 0,
		}
	}

	// Check per-client limit
	if l.config.PerClient && clientID != "" {
		client := l.getOrCreateClient(clientID)
		if !client.limiter.AllowN(time.Now(), n) {
			return &Result{
				Allowed:   false,
				Limit:     l.config.ClientRequestsPerSecond,
				Remaining: 0,
			}
		}
	}

	return &Result{Allowed: true}
}

// Wait waits until a request is allowed or context is cancelled.
func (l *Limiter) Wait(ctx context.Context, clientID string) error {
	if !l.config.Enabled {
		return nil
	}

	if l.exemptSet[clientID] {
		return nil
	}

	// Wait on global limiter
	if err := l.global.Wait(ctx); err != nil {
		return err
	}

	// Wait on per-client limiter
	if l.config.PerClient && clientID != "" {
		client := l.getOrCreateClient(clientID)
		if err := client.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (l *Limiter) getOrCreateClient(clientID string) *clientLimiter {
	l.clientsMu.RLock()
	client, exists := l.clients[clientID]
	l.clientsMu.RUnlock()

	if exists {
		client.lastSeen = time.Now()
		return client
	}

	l.clientsMu.Lock()
	defer l.clientsMu.Unlock()

	// Double-check after acquiring write lock
	if client, exists = l.clients[clientID]; exists {
		client.lastSeen = time.Now()
		return client
	}

	client = &clientLimiter{
		limiter:  rate.NewLimiter(rate.Limit(l.config.ClientRequestsPerSecond), l.config.ClientBurst),
		lastSeen: time.Now(),
	}
	l.clients[clientID] = client

	return client
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanupExpired()
		case <-l.stopCleanup:
			return
		}
	}
}

func (l *Limiter) cleanupExpired() {
	l.clientsMu.Lock()
	defer l.clientsMu.Unlock()

	now := time.Now()
	for clientID, client := range l.clients {
		if now.Sub(client.lastSeen) > l.config.ClientTTL {
			delete(l.clients, clientID)
		}
	}
}

// Close stops the rate limiter cleanup.
func (l *Limiter) Close() {
	close(l.stopCleanup)
}

// ClientCount returns the number of tracked clients.
func (l *Limiter) ClientCount() int {
	l.clientsMu.RLock()
	defer l.clientsMu.RUnlock()
	return len(l.clients)
}

// Middleware returns an HTTP middleware for rate limiting.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := l.extractClientID(r)

		result := l.Allow(clientID)
		if !result.Allowed {
			w.Header().Set("X-RateLimit-Limit", formatFloat(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", "0")
			if result.RetryIn > 0 {
				w.Header().Set("Retry-After", formatDuration(result.RetryIn))
			}
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) extractClientID(r *http.Request) string {
	switch l.config.ClientIdentifier {
	case "ip":
		// Try X-Forwarded-For first
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return xff
		}
		return r.RemoteAddr

	case "header":
		return r.Header.Get(l.config.HeaderName)

	case "cert":
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			return r.TLS.PeerCertificates[0].Subject.CommonName
		}
		return ""

	default:
		return r.RemoteAddr
	}
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.0f", f)
}

func formatDuration(d time.Duration) string {
	return fmt.Sprintf("%.0f", d.Seconds())
}
