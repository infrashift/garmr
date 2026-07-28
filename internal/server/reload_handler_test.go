package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// POST /v1/policies/reload must succeed against a good tree (200 + digest)
// and fail closed against a broken one (500, previous set still listed).
func TestHandleReloadPolicies_FailClosed(t *testing.T) {
	dir := t.TempDir()
	writeLifecyclePolicy(t, dir)

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPoliciesFromDir(context.Background(), dir); loadErr != nil {
		t.Fatalf("initial load: %v", loadErr)
	}

	srv, err := NewServer(Config{PolicyDir: dir}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Successful reload reports the digest.
	resp, err := http.Post(ts.URL+"/v1/policies/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var ok struct {
		Success bool   `json:"success"`
		Digest  string `json:"digest"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&ok); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !ok.Success || len(ok.Digest) != 64 {
		t.Fatalf("good reload: status=%d body=%+v", resp.StatusCode, ok)
	}

	// Break the tree: reload must 500 and keep the old set serving.
	if writeErr := os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(`package policy

broken: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: name: "broken"
	spec: {
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "B-1"
			description: "bad severity"
			severity:    "catastrophic"
			expr: {match: {path: "x", equals: 1}}
		}]
		enforcement: action: "deny"
	}
}
`), 0644); writeErr != nil {
		t.Fatal(writeErr)
	}

	resp, err = http.Post(ts.URL+"/v1/policies/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("broken reload: status=%d, want 500", resp.StatusCode)
	}

	// The previous set must still be loaded and its digest unchanged.
	resp, err = http.Get(ts.URL + "/v1/policies")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Digest   string `json:"digest"`
		Policies []struct {
			Name string `json:"name"`
		} `json:"policies"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&list); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	resp.Body.Close()
	if list.Digest != ok.Digest {
		t.Errorf("digest changed after failed reload: %s != %s", list.Digest, ok.Digest)
	}
	found := false
	for _, p := range list.Policies {
		if strings.Contains(p.Name, "lifecycle-policy") {
			found = true
		}
	}
	if !found {
		t.Errorf("old policy set lost after failed reload: %+v", list.Policies)
	}
}
