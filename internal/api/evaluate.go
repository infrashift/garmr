// Package api holds the /v1/evaluate wire format: the response body the
// server writes and the converter from an engine response. It is shared by
// the server and by `garmr eval --local`, so a local evaluation renders
// exactly what the same evaluation over HTTP would.
package api

import (
	"time"

	"github.com/infrashift/garmr/internal/engine"
)

// DefaultEvaluationTimeout bounds a single evaluation when none is configured.
const DefaultEvaluationTimeout = 10 * time.Second

// EvaluateBody is the /v1/evaluate response. It carries the fields the
// engine has always computed and `garmr eval --help` promises: summary,
// evaluation_mode, terminated_early and termination_rule.
type EvaluateBody struct {
	Decision        engine.Decision    `json:"decision"`
	RequestID       string             `json:"request_id"`
	Results         []RuleResultBody   `json:"results"`
	Summary         SummaryBody        `json:"summary"`
	EvaluationMode  EvaluationModeBody `json:"evaluation_mode"`
	TerminatedEarly bool               `json:"terminated_early"`
	TerminationRule *TerminationBody   `json:"termination_rule,omitempty"`
	Metrics         *MetricsBody       `json:"metrics,omitempty"`
}

// RuleResultBody is one rule's outcome.
type RuleResultBody struct {
	PolicyName      string          `json:"policy_name"`
	PolicyNamespace string          `json:"policy_namespace"`
	RuleID          string          `json:"rule_id"`
	Description     string          `json:"description"`
	Severity        engine.Severity `json:"severity"`
	Passed          bool            `json:"passed"`
	Message         string          `json:"message"`
	Remediation     string          `json:"remediation"`

	// Findings are the failing forEach elements, for rules that declare
	// `details`. FindingsTruncated is set when more failed than were listed.
	Findings          []FindingBody `json:"findings,omitempty"`
	FindingsTruncated bool          `json:"findings_truncated,omitempty"`
}

// FindingBody is one failing forEach element.
type FindingBody struct {
	Path    string         `json:"path"`
	Index   int            `json:"index"`
	Details map[string]any `json:"details,omitempty"`
}

// SummaryBody counts rule outcomes.
type SummaryBody struct {
	TotalRules int `json:"total_rules"`
	Passed     int `json:"passed"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
}

// EvaluationModeBody describes how the evaluation ran. Field order mirrors
// engine.EvaluationMode so it converts directly.
type EvaluationModeBody struct {
	FailFast          bool `json:"fail_fast"`
	ShortCircuited    bool `json:"short_circuited"`
	TotalRulesInScope int  `json:"total_rules_in_scope"`
	RulesEvaluated    int  `json:"rules_evaluated"`
	RulesSkipped      int  `json:"rules_skipped"`
	DryRun            bool `json:"dry_run"`
}

// TerminationBody names the rule that ended a fail-fast evaluation.
type TerminationBody struct {
	PolicyName      string          `json:"policy_name"`
	PolicyNamespace string          `json:"policy_namespace"`
	RuleID          string          `json:"rule_id"`
	Description     string          `json:"description"`
	Severity        engine.Severity `json:"severity"`
	Message         string          `json:"message"`
}

// MetricsBody carries evaluation counters.
type MetricsBody struct {
	EvaluationTimeNs  int64 `json:"evaluation_time_ns"`
	PoliciesEvaluated int   `json:"policies_evaluated"`
	RulesEvaluated    int   `json:"rules_evaluated"`
}

// NewEvaluateBody converts an engine response into the JSON body.
func NewEvaluateBody(result *engine.EvaluateResponse, requestID string) EvaluateBody {
	body := EvaluateBody{
		Decision:        result.Decision,
		RequestID:       requestID,
		Results:         make([]RuleResultBody, len(result.Results)),
		Summary:         SummaryBody(result.Summary),
		EvaluationMode:  EvaluationModeBody(result.EvaluationMode),
		TerminatedEarly: result.TerminatedEarly,
	}
	for i, r := range result.Results {
		body.Results[i] = RuleResultBody{
			PolicyName:        r.PolicyName,
			PolicyNamespace:   r.PolicyNamespace,
			RuleID:            r.RuleID,
			Description:       r.RuleDescription,
			Severity:          r.Severity,
			Passed:            r.Passed,
			Message:           r.Message,
			Remediation:       r.Remediation,
			Findings:          findingBodies(r.Findings),
			FindingsTruncated: r.FindingsTruncated,
		}
	}
	if tr := result.TerminationRule; tr != nil {
		body.TerminationRule = &TerminationBody{
			PolicyName:      tr.PolicyName,
			PolicyNamespace: tr.PolicyNamespace,
			RuleID:          tr.RuleID,
			Description:     tr.RuleDescription,
			Severity:        tr.Severity,
			Message:         tr.Message,
		}
	}
	if m := result.Metrics; m != nil {
		body.Metrics = &MetricsBody{
			EvaluationTimeNs:  m.EvaluationTimeNs,
			PoliciesEvaluated: m.PoliciesEvaluated,
			RulesEvaluated:    m.RulesEvaluated,
		}
	}
	return body
}

// findingBodies converts engine findings, keeping nil for none so the field
// is omitted.
func findingBodies(fs []engine.Finding) []FindingBody {
	if len(fs) == 0 {
		return nil
	}
	out := make([]FindingBody, len(fs))
	for i, f := range fs {
		out[i] = FindingBody(f)
	}
	return out
}
