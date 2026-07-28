package server

import (
	"net/http"
	"strings"
	"testing"
)

// Behind a Consul/Envoy sidecar every caller shares one RemoteAddr (the
// local proxy), so per-client buckets must key on the mesh-verified SPIFFE
// identity instead. This drives the full middleware chain: caller A exhausts
// its own bucket and is 429'd while caller B — same source address,
// different identity — keeps evaluating.
func TestRateLimit_KeyedByMeshIdentity(t *testing.T) {
	perClient := true
	ts := setupTestServer(t, Config{
		RateLimitEnabled:          true,
		RateLimitPerSecond:        10000, // global stays out of the way
		RateLimitBurst:            10000,
		RateLimitPerClient:        &perClient,
		RateLimitClientIdentifier: "identity",
		RateLimitClientRPS:        0.5,
		RateLimitClientBurst:      2,
	})
	defer ts.Close()

	post := func(identity string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/evaluate",
			strings.NewReader(`{"input": {"env": "prod"}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Client-Cert", "Hash=abc;URI="+identity)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Caller A: burst of 2, third request must be limited.
	for i := 0; i < 2; i++ {
		if status := post("spiffe://dc1/svc/a"); status != http.StatusOK {
			t.Fatalf("caller A request %d: status %d, want 200", i, status)
		}
	}
	if status := post("spiffe://dc1/svc/a"); status != http.StatusTooManyRequests {
		t.Fatalf("caller A past its burst: status %d, want 429", status)
	}

	// Caller B arrives from the same address but a different identity: its
	// own bucket, so it must still be allowed.
	if status := post("spiffe://dc1/svc/b"); status != http.StatusOK {
		t.Fatalf("caller B: status %d, want 200 (own bucket)", status)
	}
}
