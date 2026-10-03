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

// Caller-controlled audit fields must be bounded.
//
// With audit.path=stdout each record is one write to a pipe, and writes above
// PIPE_BUF (4 KiB on Linux) are not atomic. A caller sending a large
// User-Agent or X-Request-Id — both well inside Go's 1 MiB header budget —
// could push a record past that bound and have it interleave with another's,
// corrupting exactly the log that is meant to be the authoritative decision
// trail. The record must stay parseable as one JSON line.
func TestAudit_TruncatesCallerControlledFields(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	os.Stdout = w
	restore := func() { os.Stdout = origStdout }
	defer restore()

	srv, err := NewServer(Config{AuditEnabled: true, AuditPath: "stdout"}, eng, zap.NewNop())
	if err != nil {
		restore()
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	hostile := strings.Repeat("A", 10000)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/evaluate",
		strings.NewReader(`{"input": {"env": "prod", "kind": "`+hostile+`"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", hostile)
	req.Header.Set("X-Request-Id", hostile)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		restore()
		t.Fatal(err)
	}
	resp.Body.Close()

	if stopErr := srv.Stop(); stopErr != nil {
		restore()
		t.Fatalf("Stop: %v", stopErr)
	}
	w.Close()
	restore()
	captured, _ := io.ReadAll(r)

	var record map[string]any
	var line string
	for _, l := range strings.Split(string(captured), "\n") {
		if strings.Contains(l, `"decision"`) {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("no decision audit record on stdout; captured %d bytes", len(captured))
	}
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("audit record is not valid JSON: %v", err)
	}

	// The whole record must fit in an atomic pipe write.
	if len(line) >= 4096 {
		t.Errorf("audit record is %d bytes, want < 4096 (PIPE_BUF) so the write stays atomic", len(line))
	}

	for _, field := range []string{"user_agent", "request_id", "input_kind"} {
		v, ok := record[field].(string)
		if !ok {
			t.Errorf("%s missing from audit record", field)
			continue
		}
		if len(v) > maxAuditFieldBytes+len("…[truncated]") {
			t.Errorf("%s is %d bytes, want it truncated to ~%d", field, len(v), maxAuditFieldBytes)
		}
		if !strings.HasSuffix(v, "[truncated]") {
			t.Errorf("%s was shortened without being marked truncated: %q", field, v)
		}
	}
}

// Truncation must not touch values that are already within bounds, or every
// ordinary audit record would carry a misleading marker.
func TestAuditField_LeavesNormalValuesIntact(t *testing.T) {
	for _, s := range []string{"", "spiffe://dc1/ns/default/sa/ci", strings.Repeat("x", maxAuditFieldBytes)} {
		if got := auditField(s); got != s {
			t.Errorf("auditField(%d bytes) modified a value within bounds", len(s))
		}
	}

	long := strings.Repeat("x", maxAuditFieldBytes+1)
	got := auditField(long)
	if got == long {
		t.Error("auditField did not truncate an over-long value")
	}
	if !strings.HasSuffix(got, "[truncated]") {
		t.Errorf("truncated value not marked: %q", got)
	}
}

// Non-string input values pass through: only strings are unbounded here, and
// coercing everything to a string would lose type information in the trail.
func TestAuditAny_PreservesNonStrings(t *testing.T) {
	if got := auditAny(42); got != 42 {
		t.Errorf("auditAny(42) = %v, want 42", got)
	}
	if got := auditAny(nil); got != nil {
		t.Errorf("auditAny(nil) = %v, want nil", got)
	}
	long := strings.Repeat("x", maxAuditFieldBytes+1)
	if got := auditAny(long); got == long {
		t.Error("auditAny did not truncate an over-long string")
	}
}
