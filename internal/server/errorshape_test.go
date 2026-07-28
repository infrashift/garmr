package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Every error response must carry the same shape: application/json with an
// "error" string. Clients parse bodies based on this; a plain-text stray
// means resp.json() blows up depending on WHICH 400/405 they hit.
func TestErrorResponses_AllJSON(t *testing.T) {
	cases := []struct {
		name       string
		cfg        Config
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "evaluate method not allowed",
			method:     http.MethodGet,
			path:       "/v1/evaluate",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "validate method not allowed",
			method:     http.MethodGet,
			path:       "/v1/validate",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "policies method not allowed",
			method:     http.MethodPut,
			path:       "/v1/policies",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "reload method not allowed",
			method:     http.MethodGet,
			path:       "/v1/policies/reload",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "evaluate missing input",
			method:     http.MethodPost,
			path:       "/v1/evaluate",
			body:       `{"namespace": "default"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "evaluate malformed body",
			method:     http.MethodPost,
			path:       "/v1/evaluate",
			body:       `{{{ not json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "evaluate body too large",
			cfg:        Config{MaxRecvSize: 64},
			method:     http.MethodPost,
			path:       "/v1/evaluate",
			body:       `{"input": {"pad": "` + strings.Repeat("x", 256) + `"}}`,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "validate body too large",
			cfg:        Config{MaxRecvSize: 64},
			method:     http.MethodPost,
			path:       "/v1/validate",
			body:       `{"policy": "` + strings.Repeat("x", 256) + `"}`,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "reload without a policy source",
			method:     http.MethodPost,
			path:       "/v1/policies/reload",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unauthorized",
			cfg:        Config{APIKey: "secret"},
			method:     http.MethodPost,
			path:       "/v1/evaluate",
			body:       `{"input": {"env": "prod"}}`,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := setupTestServer(t, tc.cfg)
			defer ts.Close()

			req, err := http.NewRequest(tc.method, ts.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("error body is not JSON: %v", err)
			}
			if body.Error == "" {
				t.Error(`error body is missing the "error" field`)
			}
		})
	}
}

// The rate limiter's 429 must carry the same JSON shape; it writes its
// response from inside the middleware, not via the server's writeError.
func TestErrorResponses_RateLimitedJSON(t *testing.T) {
	ts := setupTestServer(t, Config{
		RateLimitEnabled:   true,
		RateLimitPerSecond: 0.001,
		RateLimitBurst:     1,
	})
	defer ts.Close()

	// Exhaust the burst, then expect a JSON 429.
	var last *http.Response
	for i := 0; i < 3; i++ {
		resp, err := http.Post(ts.URL+"/v1/evaluate", "application/json",
			strings.NewReader(`{"input": {"env": "prod"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if last != nil {
			last.Body.Close()
		}
		last = resp
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
	}
	defer last.Body.Close()

	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("never rate limited; final status %d", last.StatusCode)
	}
	if ct := last.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(last.Body).Decode(&body); err != nil {
		t.Fatalf("429 body is not JSON: %v", err)
	}
	if body.Error == "" {
		t.Error(`429 body is missing the "error" field`)
	}
}
