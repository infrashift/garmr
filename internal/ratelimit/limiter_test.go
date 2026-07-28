package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.RequestsPerSecond = 1000
	cfg.Burst = 1000
	cfg.ClientRequestsPerSecond = 1000
	cfg.ClientBurst = 1000
	cfg.CleanupInterval = 0 // no background goroutine unless a test wants one
	return cfg
}

func TestAllow_Disabled(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	cfg.Burst = 0
	cfg.RequestsPerSecond = 0
	l := New(cfg)
	defer l.Close()

	for i := 0; i < 10; i++ {
		if got := l.Allow("1.2.3.4"); !got.Allowed {
			t.Fatalf("request %d denied while rate limiting is disabled", i)
		}
	}
}

func TestAllow_GlobalBurstExhausted(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = false
	cfg.RequestsPerSecond = 1
	cfg.Burst = 3
	l := New(cfg)
	defer l.Close()

	for i := 0; i < 3; i++ {
		if got := l.Allow(""); !got.Allowed {
			t.Fatalf("request %d denied within burst of 3", i)
		}
	}
	if got := l.Allow(""); got.Allowed {
		t.Error("request past the global burst was allowed")
	}
}

func TestAllow_PerClientIsolation(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = true
	cfg.ClientRequestsPerSecond = 1
	cfg.ClientBurst = 2
	l := New(cfg)
	defer l.Close()

	for i := 0; i < 2; i++ {
		if got := l.Allow("client-a"); !got.Allowed {
			t.Fatalf("client-a request %d denied within its burst", i)
		}
	}
	if got := l.Allow("client-a"); got.Allowed {
		t.Error("client-a exceeded its burst but was allowed")
	}
	// A different client must have its own bucket.
	if got := l.Allow("client-b"); !got.Allowed {
		t.Error("client-b was denied because client-a exhausted its own bucket")
	}
}

func TestAllow_ExemptClient(t *testing.T) {
	cfg := testConfig()
	cfg.RequestsPerSecond = 1
	cfg.Burst = 1
	cfg.ExemptClients = []string{"trusted"}
	l := New(cfg)
	defer l.Close()

	for i := 0; i < 20; i++ {
		if got := l.Allow("trusted"); !got.Allowed {
			t.Fatalf("exempt client denied on request %d", i)
		}
	}
}

func TestAllowN(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = false
	cfg.RequestsPerSecond = 1
	cfg.Burst = 5
	l := New(cfg)
	defer l.Close()

	if got := l.AllowN("", 5); !got.Allowed {
		t.Fatal("AllowN(5) denied within a burst of 5")
	}
	if got := l.AllowN("", 5); got.Allowed {
		t.Error("AllowN(5) allowed after the burst was consumed")
	}
}

func TestWait_CancelledContext(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = false
	cfg.RequestsPerSecond = 0.0001
	cfg.Burst = 1
	l := New(cfg)
	defer l.Close()

	// Consume the burst.
	if err := l.Wait(context.Background(), ""); err != nil {
		t.Fatalf("first Wait failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx, ""); err == nil {
		t.Error("Wait returned nil after its context expired")
	}
}

func TestWait_Disabled(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	l := New(cfg)
	defer l.Close()

	if err := l.Wait(context.Background(), "x"); err != nil {
		t.Errorf("Wait failed while disabled: %v", err)
	}
}

// TestExtractClientID_XForwardedForRequiresTrustedProxy is the security case.
// The header used to be trusted unconditionally, so any caller could rotate
// it to get a fresh bucket per request — bypassing the per-client limit and
// growing the client map without bound.
func TestExtractClientID_XForwardedForRequiresTrustedProxy(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xff            string
		want           string
	}{
		{
			name:       "no trusted proxies: header ignored",
			remoteAddr: "10.0.0.5:5555",
			xff:        "1.2.3.4",
			want:       "10.0.0.5",
		},
		{
			name:           "untrusted peer: header ignored",
			trustedProxies: []string{"192.168.0.0/16"},
			remoteAddr:     "10.0.0.5:5555",
			xff:            "1.2.3.4",
			want:           "10.0.0.5",
		},
		{
			name:           "trusted peer: header believed",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:5555",
			xff:            "1.2.3.4",
			want:           "1.2.3.4",
		},
		{
			name:           "trusted peer: right-most entry wins",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:5555",
			xff:            "spoofed, 9.9.9.9, 1.2.3.4",
			want:           "1.2.3.4",
		},
		{
			name:       "no header: port stripped from RemoteAddr",
			remoteAddr: "203.0.113.9:41234",
			want:       "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.ClientIdentifier = "ip"
			cfg.TrustedProxies = tt.trustedProxies
			l := New(cfg)
			defer l.Close()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			if got := l.extractClientID(req); got != tt.want {
				t.Errorf("extractClientID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractClientID_HeaderMode(t *testing.T) {
	cfg := testConfig()
	cfg.ClientIdentifier = "header"
	cfg.HeaderName = "X-Client-ID"
	l := New(cfg)
	defer l.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Client-ID", "team-a")
	if got := l.extractClientID(req); got != "team-a" {
		t.Errorf("extractClientID = %q, want %q", got, "team-a")
	}
}

func TestExtractClientID_UnknownModeFallsBackToIP(t *testing.T) {
	cfg := testConfig()
	// "cert" was removed with the TLS listener (the server never terminates
	// TLS, so peer certificates cannot exist); unknown identifiers fall back
	// to the client IP.
	cfg.ClientIdentifier = "cert"
	l := New(cfg)
	defer l.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:4567"
	if got := l.extractClientID(req); got != "10.1.2.3" {
		t.Errorf("extractClientID = %q, want the client IP fallback", got)
	}
}

// TestClientMap_BoundedByMaxClients covers the memory bound. A caller
// rotating its identifier must not grow the map without limit.
func TestClientMap_BoundedByMaxClients(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = true
	cfg.MaxClients = 16
	l := New(cfg)
	defer l.Close()

	for i := 0; i < 1000; i++ {
		l.Allow(string(rune('a'+i%26)) + string(rune('0'+i%10)) + time.Duration(i).String())
	}

	if got := l.ClientCount(); got > cfg.MaxClients {
		t.Errorf("client map holds %d entries, want at most %d", got, cfg.MaxClients)
	}
}

func TestCleanupExpired(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = true
	cfg.ClientTTL = time.Nanosecond
	l := New(cfg)
	defer l.Close()

	l.Allow("client-a")
	l.Allow("client-b")
	if l.ClientCount() != 2 {
		t.Fatalf("ClientCount = %d, want 2", l.ClientCount())
	}

	time.Sleep(time.Millisecond)
	l.cleanupExpired()

	if got := l.ClientCount(); got != 0 {
		t.Errorf("ClientCount after cleanup = %d, want 0", got)
	}
}

// TestClose_Idempotent covers the double-Stop panic: Close used to close an
// unguarded channel, so a second Server.Stop() crashed the process.
func TestClose_Idempotent(t *testing.T) {
	l := New(testConfig())
	l.Close()
	l.Close() // must not panic
}

func TestMiddleware_LimitedResponse(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = false
	cfg.RequestsPerSecond = 1
	cfg.Burst = 1
	l := New(cfg)
	defer l.Close()

	var limitedCalls int
	l.SetOnLimited(func() { limitedCalls++ })

	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", second.Code)
	}
	if got := second.Header().Get("X-RateLimit-Limit"); got == "" {
		t.Error("429 response is missing X-RateLimit-Limit")
	}
	if got := second.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Errorf("X-RateLimit-Remaining = %q, want %q", got, "0")
	}
	if got := second.Header().Get("Retry-After"); got == "" {
		t.Error("429 response is missing Retry-After")
	}

	// The limiter was previously unobservable: the Prometheus collector was
	// registered but never incremented.
	if limitedCalls != 1 {
		t.Errorf("onLimited called %d times, want 1", limitedCalls)
	}
}

// TestConcurrentAllowAndCleanup exercises the lastSeen race directly. Under
// -race this fails when lastSeen is a plain time.Time written outside the
// lock, which is how it used to be.
func TestConcurrentAllowAndCleanup(t *testing.T) {
	cfg := testConfig()
	cfg.PerClient = true
	cfg.ClientTTL = time.Microsecond
	l := New(cfg)
	defer l.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				l.cleanupExpired()
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				l.Allow(string(rune('a' + (i+j)%26)))
				l.ClientCount()
			}
		}(i)
	}

	// Writers finish; then stop the cleanup loop.
	go func() {
		for j := 0; j < 500; j++ {
			l.Allow("steady")
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	// wg includes the cleanup goroutine, so signal it once the workers are in
	// flight and then wait.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	<-done
}
