// Package ratelimit provides request rate limiting for Garmr.
//
// Placement note: this middleware must sit OUTSIDE authMiddleware in the
// handler chain. Composed inside it, unauthenticated floods are rejected by
// auth before the limiter ever sees them, which is precisely the traffic
// worth limiting.
package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/infrashift/garmr/internal/xfcc"
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

	// ClientIdentifier is how to identify clients: "ip", "header", or
	// "identity". Behind a service-mesh sidecar (Consul transparent proxy),
	// "ip" collapses every caller into one bucket — RemoteAddr is the local
	// Envoy — so mesh deployments should use "identity", which keys on the
	// SPIFFE URI the sidecar forwards in the XFCC header. Only enable
	// "identity" when a sidecar owns that header: from untrusted callers it
	// is spoofable, letting them rotate buckets at will.
	ClientIdentifier string `json:"clientIdentifier"`

	// HeaderName for header-based client identification
	HeaderName string `json:"headerName"`

	// IdentityHeader is the header carrying the mesh-verified identity for
	// the "identity" client identifier. Empty means xfcc.DefaultHeader.
	IdentityHeader string `json:"identityHeader"`

	// CleanupInterval for expired client limiters
	CleanupInterval time.Duration `json:"cleanupInterval"`

	// ClientTTL is how long to keep inactive client limiters
	ClientTTL time.Duration `json:"clientTtl"`

	// ExemptClients are client identifiers exempt from rate limiting
	ExemptClients []string `json:"exemptClients"`

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed
	// when ClientIdentifier is "ip". Empty means never trust the header.
	//
	// Without this the header is attacker-controlled: any client can rotate
	// it to get a fresh bucket per request, which both bypasses the per-client
	// limit and grows the client map without bound.
	TrustedProxies []string `json:"trustedProxies"`

	// MaxClients bounds the per-client limiter map. Reaching it evicts the
	// least recently seen client. Zero uses DefaultMaxClients.
	MaxClients int `json:"maxClients"`
}

// DefaultMaxClients bounds the client map when Config.MaxClients is unset.
const DefaultMaxClients = 10000

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
		MaxClients:              DefaultMaxClients,
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

	// trustedProxies are the parsed Config.TrustedProxies CIDRs.
	trustedProxies []*net.IPNet

	// maxClients is the resolved bound on the clients map.
	maxClients int

	// onLimited, when set, is called each time a request is rejected. The
	// server wires this to the garmr_rate_limit_hits_total metric.
	onLimited func()

	// Cleanup
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

type clientLimiter struct {
	limiter *rate.Limiter
	// lastSeen is unix nanos, accessed atomically. It was previously a
	// time.Time written after releasing the read lock while cleanupExpired
	// read it under the write lock — an unsynchronised race.
	lastSeen atomic.Int64
}

func (c *clientLimiter) touch() {
	c.lastSeen.Store(time.Now().UnixNano())
}

// New creates a new rate limiter.
func New(cfg Config) *Limiter {
	l := &Limiter{
		config:      cfg,
		clients:     make(map[string]*clientLimiter),
		exemptSet:   make(map[string]bool),
		maxClients:  cfg.MaxClients,
		stopCleanup: make(chan struct{}),
	}

	if l.maxClients <= 0 {
		l.maxClients = DefaultMaxClients
	}

	// Create global limiter
	l.global = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)

	// Build exempt set
	for _, client := range cfg.ExemptClients {
		l.exemptSet[client] = true
	}

	// Parse trusted proxy CIDRs. A malformed entry is skipped rather than
	// silently widening trust.
	for _, cidr := range cfg.TrustedProxies {
		if _, network, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
			l.trustedProxies = append(l.trustedProxies, network)
		}
	}

	// Start cleanup goroutine
	if cfg.PerClient && cfg.CleanupInterval > 0 {
		go l.cleanup()
	}

	return l
}

// SetOnLimited registers a callback invoked whenever a request is rejected.
func (l *Limiter) SetOnLimited(fn func()) {
	l.onLimited = fn
}

func (l *Limiter) limited() {
	if l.onLimited != nil {
		l.onLimited()
	}
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
			RetryIn:   retryIn(l.config.RequestsPerSecond),
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
				RetryIn:   retryIn(l.config.ClientRequestsPerSecond),
			}
		}
	}

	return &Result{
		Allowed: true,
		Limit:   l.config.RequestsPerSecond,
	}
}

// retryIn converts a rate into the wait before the next token. The naive
// `time.Second / time.Duration(rps)` truncated fractional rates to zero and
// panicked with a divide-by-zero, so any limiter configured below 1 rps
// turned every rejected request into a 500 instead of a 429.
func retryIn(rps float64) time.Duration {
	if rps <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / rps)
}

func (l *Limiter) getOrCreateClient(clientID string) *clientLimiter {
	l.clientsMu.RLock()
	client, exists := l.clients[clientID]
	l.clientsMu.RUnlock()

	if exists {
		client.touch()
		return client
	}

	l.clientsMu.Lock()
	defer l.clientsMu.Unlock()

	// Double-check after acquiring write lock
	if client, exists = l.clients[clientID]; exists {
		client.touch()
		return client
	}

	// Bound the map. Without this a caller rotating its identifier (e.g. a
	// spoofed X-Forwarded-For) grows it without limit.
	if len(l.clients) >= l.maxClients {
		l.evictOldestLocked()
	}

	client = &clientLimiter{
		limiter: rate.NewLimiter(rate.Limit(l.config.ClientRequestsPerSecond), l.config.ClientBurst),
	}
	client.touch()
	l.clients[clientID] = client

	return client
}

// evictOldestLocked removes the least recently seen client. Caller holds the
// write lock.
func (l *Limiter) evictOldestLocked() {
	var oldestID string
	var oldest int64

	for id, c := range l.clients {
		seen := c.lastSeen.Load()
		if oldestID == "" || seen < oldest {
			oldestID, oldest = id, seen
		}
	}
	if oldestID != "" {
		delete(l.clients, oldestID)
	}
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

	cutoff := time.Now().Add(-l.config.ClientTTL).UnixNano()
	for clientID, client := range l.clients {
		if client.lastSeen.Load() < cutoff {
			delete(l.clients, clientID)
		}
	}
}

// Close stops the rate limiter cleanup. Safe to call more than once:
// Server.Stop can run twice, and closing an already-closed channel panics.
func (l *Limiter) Close() {
	l.closeOnce.Do(func() {
		close(l.stopCleanup)
	})
}

// Middleware returns an HTTP middleware for rate limiting.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := l.extractClientID(r)

		result := l.Allow(clientID)
		if !result.Allowed {
			l.limited()
			w.Header().Set("X-RateLimit-Limit", formatFloat(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", "0")
			if result.RetryIn > 0 {
				w.Header().Set("Retry-After", formatDuration(result.RetryIn))
			}
			// Same {"error": ...} JSON shape as every other error response.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}` + "\n"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) extractClientID(r *http.Request) string {
	switch l.config.ClientIdentifier {
	case "ip":
		// X-Forwarded-For is only believed when the immediate peer is a
		// configured trusted proxy. Trusting it unconditionally let any
		// client rotate the header for a fresh bucket per request, which
		// both bypassed the per-client limit and grew the client map.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" && l.peerIsTrustedProxy(r.RemoteAddr) {
			// Right-most entry appended by our trusted proxy is the only one
			// it vouches for; earlier entries are caller-supplied.
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
		return clientIP(r.RemoteAddr)

	case "header":
		return r.Header.Get(l.config.HeaderName)

	case "identity":
		// Key on the mesh-verified SPIFFE identity from the XFCC header.
		// Falls back to the client IP when the header is absent or carries
		// no URI — behind a sidecar that collapses to the loopback bucket,
		// which fails safe (shared limit) rather than open (fresh buckets).
		header := l.config.IdentityHeader
		if header == "" {
			header = xfcc.DefaultHeader
		}
		if id := xfcc.ParseSPIFFEIdentity(r.Header.Values(header)); id != "" {
			return id
		}
		return clientIP(r.RemoteAddr)

	default:
		return clientIP(r.RemoteAddr)
	}
}

// peerIsTrustedProxy reports whether the immediate peer falls inside a
// configured TrustedProxies CIDR. With none configured this is always false,
// so X-Forwarded-For is ignored by default.
func (l *Limiter) peerIsTrustedProxy(remoteAddr string) bool {
	if len(l.trustedProxies) == 0 {
		return false
	}
	ip := net.ParseIP(clientIP(remoteAddr))
	if ip == nil {
		return false
	}
	for _, network := range l.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP strips the port from a RemoteAddr, so one client's buckets are not
// split across its ephemeral source ports.
func clientIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.0f", f)
}

func formatDuration(d time.Duration) string {
	return fmt.Sprintf("%.0f", d.Seconds())
}
