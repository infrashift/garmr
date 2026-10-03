package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scrape returns the metrics exposition text.
func scrape(t *testing.T, m *PrometheusMetrics) string {
	t.Helper()
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestRecordPolicyReload_CountsByResult(t *testing.T) {
	m := NewPrometheusMetrics()
	m.RecordPolicyReload(true)
	m.RecordPolicyReload(true)
	m.RecordPolicyReload(false)

	out := scrape(t, m)
	if !strings.Contains(out, `garmr_policy_reloads_total{result="success"} 2`) {
		t.Errorf("missing success=2 in:\n%s", out)
	}
	if !strings.Contains(out, `garmr_policy_reloads_total{result="failure"} 1`) {
		t.Errorf("missing failure=1 in:\n%s", out)
	}
}

// SetPoliciesLoaded is a full snapshot: a namespace missing from the new
// snapshot must drop out of the series entirely, not keep its last value.
func TestSetPoliciesLoaded_SnapshotDropsVanishedNamespaces(t *testing.T) {
	m := NewPrometheusMetrics()

	m.SetPoliciesLoaded(map[string]int{"team-a": 2, "team-b": 1})
	out := scrape(t, m)
	if !strings.Contains(out, `garmr_policies_loaded{namespace="team-a"} 2`) ||
		!strings.Contains(out, `garmr_policies_loaded{namespace="team-b"} 1`) {
		t.Fatalf("initial snapshot not published:\n%s", out)
	}

	// team-b disappears (e.g. its policies were removed in a reload).
	m.SetPoliciesLoaded(map[string]int{"team-a": 1})
	out = scrape(t, m)
	if !strings.Contains(out, `garmr_policies_loaded{namespace="team-a"} 1`) {
		t.Errorf("team-a not updated:\n%s", out)
	}
	if strings.Contains(out, `namespace="team-b"`) {
		t.Errorf("vanished namespace team-b still exported:\n%s", out)
	}
}
