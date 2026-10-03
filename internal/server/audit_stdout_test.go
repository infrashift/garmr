package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// audit.path "stdout" streams audit records to the process stdout so the
// platform's log pipeline ships them off-node — the audit trail is the only
// record of the mesh-verified principal. This drives a real evaluation and
// asserts the decision record (principal included) lands on stdout as JSON.
func TestAuditLogger_StdoutSink(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	// Capture stdout across NewServer (which binds the sink) and the request.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	restore := func() {
		os.Stdout = origStdout
	}
	defer restore()

	srv, err := NewServer(Config{AuditEnabled: true, AuditPath: "stdout"}, eng, zap.NewNop())
	if err != nil {
		restore()
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/evaluate",
		strings.NewReader(`{"input": {"env": "prod"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Client-Cert", "Hash=abc;URI=spiffe://dc1/svc/ci")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		restore()
		t.Fatal(err)
	}
	resp.Body.Close()

	// Stop must not close the process stream (auditFile is nil for streams).
	if stopErr := srv.Stop(); stopErr != nil {
		restore()
		t.Fatalf("Stop: %v", stopErr)
	}

	w.Close()
	restore()
	captured, _ := io.ReadAll(r)

	var record map[string]any
	found := false
	for _, line := range strings.Split(string(captured), "\n") {
		if !strings.Contains(line, `"decision"`) {
			continue
		}
		if jsonErr := json.Unmarshal([]byte(line), &record); jsonErr != nil {
			t.Fatalf("audit line is not JSON: %v (%q)", jsonErr, line)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("no decision audit record on stdout; captured: %q", string(captured))
	}
	if record["principal"] != "spiffe://dc1/svc/ci" {
		t.Errorf("principal = %v, want the mesh identity", record["principal"])
	}
	if record["decision"] == "" {
		t.Error("decision missing from audit record")
	}
}
