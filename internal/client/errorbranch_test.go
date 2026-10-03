package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every client method shares two failure shapes: a non-2xx status (the body
// is surfaced in the error) and a 2xx response whose body does not decode.
// This table drives all methods through both.
func TestClient_ErrorBranches(t *testing.T) {
	methods := []struct {
		name string
		call func(c *Client) error
	}{
		{"Evaluate", func(c *Client) error {
			_, err := c.Evaluate(context.Background(), map[string]any{"x": 1}, EvaluateOptions{})
			return err
		}},
		{"Validate", func(c *Client) error {
			_, err := c.Validate(context.Background(), `kind: "Policy"`)
			return err
		}},
		{"ListPolicies", func(c *Client) error {
			_, err := c.ListPolicies(context.Background(), "")
			return err
		}},
		{"DeletePolicy", func(c *Client) error {
			_, err := c.DeletePolicy(context.Background(), "name", "ns")
			return err
		}},
		{"Health", func(c *Client) error {
			_, err := c.Health(context.Background())
			return err
		}},
	}

	t.Run("non-2xx status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer server.Close()
		c, _ := NewClient(Config{Address: server.URL})
		defer c.Close()

		for _, m := range methods {
			t.Run(m.name, func(t *testing.T) {
				err := m.call(c)
				if err == nil {
					t.Fatal("expected an error for a 500 response")
				}
				if !strings.Contains(err.Error(), "boom") {
					t.Errorf("error should surface the response body, got: %v", err)
				}
			})
		}
	})

	t.Run("malformed body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"this is": not json`))
		}))
		defer server.Close()
		c, _ := NewClient(Config{Address: server.URL})
		defer c.Close()

		for _, m := range methods {
			t.Run(m.name, func(t *testing.T) {
				err := m.call(c)
				if err == nil {
					t.Fatal("expected a decode error for a malformed body")
				}
				if !strings.Contains(err.Error(), "decoding response") {
					t.Errorf("expected a decoding error, got: %v", err)
				}
			})
		}
	})

	// ReloadPolicies has bespoke error semantics: a non-200 with a JSON body
	// yields a failed result (not an error), and a malformed body errors.
	t.Run("ReloadPolicies non-200 JSON body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"success": false, "error": "reload exploded"}`))
		}))
		defer server.Close()
		c, _ := NewClient(Config{Address: server.URL})
		defer c.Close()

		result, err := c.ReloadPolicies(context.Background())
		if err != nil {
			t.Fatalf("expected a failed result, not an error: %v", err)
		}
		if result.Success || result.Error != "reload exploded" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("ReloadPolicies non-200 empty error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{}`))
		}))
		defer server.Close()
		c, _ := NewClient(Config{Address: server.URL})
		defer c.Close()

		result, err := c.ReloadPolicies(context.Background())
		if err != nil {
			t.Fatalf("expected a failed result, not an error: %v", err)
		}
		if result.Success || !strings.Contains(result.Error, "502") {
			t.Errorf("expected the status code surfaced in Error, got: %+v", result)
		}
	})

	t.Run("ReloadPolicies malformed body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`not json at all`))
		}))
		defer server.Close()
		c, _ := NewClient(Config{Address: server.URL})
		defer c.Close()

		if _, err := c.ReloadPolicies(context.Background()); err == nil {
			t.Fatal("expected a decode error for a malformed body")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		c, _ := NewClient(Config{Address: "http://127.0.0.1:1"})
		defer c.Close()
		for _, m := range methods {
			t.Run(m.name, func(t *testing.T) {
				if err := m.call(c); err == nil {
					t.Fatal("expected a transport error")
				}
			})
		}
	})
}
