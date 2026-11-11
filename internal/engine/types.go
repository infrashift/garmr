package engine

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Common errors
var (
	ErrPolicyNotFound = errors.New("policy not found")
	ErrInvalidPolicy  = errors.New("invalid policy")
	ErrInvalidInput   = errors.New("invalid input")

	// ErrEvaluationUnavailable means the evaluation never started: the
	// caller's context had already ended (deadline passed or client gone)
	// when Evaluate was called. It is backpressure, not a failed decision —
	// callers should surface it as "retry later" (503), never as a policy
	// outcome.
	ErrEvaluationUnavailable = errors.New("evaluation unavailable")
)

// Decision represents the overall evaluation decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionWarn  Decision = "warn"
)

// decisionRank orders decisions by severity: Allow < Warn < Deny.
func decisionRank(d Decision) int {
	switch d {
	case DecisionDeny:
		return 2
	case DecisionWarn:
		return 1
	default:
		return 0
	}
}

// maxDecision returns the more severe of two decisions. Aggregating with this
// makes the overall decision independent of policy evaluation order: one
// policy can never lower a decision another policy has already raised.
func maxDecision(a, b Decision) Decision {
	if decisionRank(b) > decisionRank(a) {
		return b
	}
	return a
}

// Severity levels.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityWeight returns numeric weight for severity.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 25
	default:
		return 0
	}
}

// BuiltinFunc is a function that can be called from policy expressions.
type BuiltinFunc func(ctx context.Context, args ...any) (any, error)

// CompiledPolicy represents a pre-compiled policy for fast evaluation.
type CompiledPolicy struct {
	Name        string
	Namespace   string
	Hash        string
	Source      string // directory the policy was loaded from, if any
	Rules       []CompiledRule
	Target      TargetSpec
	Enforcement EnforcementSpec
	Evaluation  EvaluationConfig
	LoadedAt    time.Time

	// inputSchema is the policy's spec.inputSchema as self-contained CUE
	// source, or "" when it declares none. Compiled only by callers that
	// set EvaluateOptions.CheckInputSchema.
	inputSchema string
}

func (p *CompiledPolicy) key() string { return policyKey(p.Namespace, p.Name) }

// CompiledRule is a pre-compiled rule within a policy.
type CompiledRule struct {
	ID          string
	Description string
	Severity    Severity
	Priority    *int // nil means not specified (use definition order)
	Message     string
	Remediation string
	Category    string
	Tags        []string
	// Internal: original position in the rules list for stable sorting
	DefinitionOrder int

	// expr is the compiled expression and msg the parsed Message template;
	// bindings and failing forEach elements are only collected when msg
	// uses them.
	expr node
	msg  msgTemplate

	// details are the rule's `details` paths, in name order. A rule with
	// details records its failing forEach elements as findings.
	details []detailPath

	// skippedBy lists the exceptions (indexes into the policy's
	// Enforcement.Exceptions) that skip this whole rule; waivesElements is
	// set when an exception waives some of its forEach elements.
	skippedBy      []int
	waivesElements bool
}

// EvaluationConfig controls rule evaluation behavior.
type EvaluationConfig struct {
	Order             EvaluationOrder
	FailFast          bool
	IncludeCategories []string
	ExcludeCategories []string
	IncludeTags       []string
	ExcludeTags       []string
	MaxRules          int
	Timeout           time.Duration
}

// EvaluationOrder defines how rules are sorted.
type EvaluationOrder string

const (
	EvalOrderPriority        EvaluationOrder = "priority"
	EvalOrderSeverity        EvaluationOrder = "severity"
	EvalOrderDefinition      EvaluationOrder = "definition"
	EvalOrderPriorityThenSev EvaluationOrder = "priority-then-severity"
)

// TargetSpec defines what resources a policy applies to.
type TargetSpec struct {
	Resources []ResourceSelector
}

// ResourceSelector identifies resources. Patterns are case-insensitive and
// "*" matches any run of characters.
type ResourceSelector struct {
	APIGroup    string            `json:"apiGroup"`
	Kind        string            `json:"kind"`
	Names       []string          `json:"names"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Namespaces  []string          `json:"namespaces"`
}

// UnmarshalJSON accepts the plain-string shorthand for a kind in any group.
func (rs *ResourceSelector) UnmarshalJSON(b []byte) error {
	var kind string
	if json.Unmarshal(b, &kind) == nil {
		*rs = ResourceSelector{Kind: kind, APIGroup: "*"}
		return nil
	}
	type plain ResourceSelector
	return json.Unmarshal(b, (*plain)(rs))
}

// narrows reports whether the selector excludes anything. Every field
// defaults to a wildcard, so a selector that narrows nothing matches every
// input.
func (rs ResourceSelector) narrows() bool {
	anySpecific := func(patterns []string) bool {
		for _, p := range patterns {
			if p != "*" {
				return true
			}
		}
		return false
	}
	return (rs.Kind != "" && rs.Kind != "*") || rs.APIGroup != "*" ||
		anySpecific(rs.Names) || anySpecific(rs.Namespaces) ||
		len(rs.Labels) > 0 || len(rs.Annotations) > 0
}

// EnforcementSpec defines enforcement behavior.
type EnforcementSpec struct {
	Action     string          `json:"action"`
	DryRun     bool            `json:"dryRun"`
	Exceptions []ExceptionSpec `json:"exceptions"`
}

// ExceptionSpec waives a policy, some of its rules, or some of their
// forEach elements, for the inputs Match selects (every input when nil),
// until Expiry if set.
type ExceptionSpec struct {
	Name     string                 `json:"name"`
	Reason   string                 `json:"reason"`
	Match    *ResourceSelector      `json:"match"`
	Expiry   *time.Time             `json:"expiry"`
	Rules    []string               `json:"rules"`
	Findings *ExceptionFindingsSpec `json:"findings"`
}

// ExceptionFindingsSpec selects the forEach elements an exception waives:
// those of the forEach with alias As for which Where holds.
type ExceptionFindingsSpec struct {
	As    string `json:"as"`
	Where any    `json:"where"`
}

// policyWide reports whether the exception skips the whole policy.
func (x ExceptionSpec) policyWide() bool { return len(x.Rules) == 0 }

// EvaluateRequest contains the input for policy evaluation.
type EvaluateRequest struct {
	Input     map[string]any
	Policies  []string // Specific policies to evaluate (empty = all matching)
	Namespace string   // Filter policies by namespace (empty = all namespaces)
	Options   EvaluateOptions
}

// EvaluateOptions controls evaluation behavior.
type EvaluateOptions struct {
	// IncludePassed returns passing rule results as well as failures.
	IncludePassed bool

	// CheckInputSchema validates the input against the spec.inputSchema of
	// each policy about to be evaluated, failing with ErrInvalidInput when
	// it does not conform. It compiles CUE per request, so the server does
	// not set it; `garmr eval --local` and `garmr test` do.
	CheckInputSchema bool
}

// EvaluateResponse contains evaluation results.
type EvaluateResponse struct {
	Decision Decision
	Results  []RuleResult
	Metrics  *Metrics

	// Evaluation metadata
	EvaluationMode EvaluationMode

	// If FailFast was triggered, this contains the terminating result
	TerminatedEarly bool
	TerminationRule *RuleResult

	// Summary counts
	Summary ResultSummary
}

// EvaluationMode indicates how evaluation was performed.
type EvaluationMode struct {
	// Whether fail-fast was enabled
	FailFast bool
	// Whether evaluation was terminated early due to fail-fast
	ShortCircuited bool
	// Total rules that would have been evaluated without short-circuit
	TotalRulesInScope int
	// Rules actually evaluated before termination
	RulesEvaluated int
	// Rules skipped due to short-circuit
	RulesSkipped int
	// Whether dry run mode was active
	DryRun bool
}

// ResultSummary provides aggregate counts.
type ResultSummary struct {
	TotalRules int
	Passed     int
	Failed     int
	Skipped    int
}

// RuleResult is the result of evaluating a single rule.
type RuleResult struct {
	PolicyName      string
	PolicyNamespace string
	RuleID          string
	RuleDescription string
	Severity        Severity
	Passed          bool
	Message         string
	Remediation     string
	Bindings        map[string]any

	// Findings lists the failing forEach elements, for rules that declare
	// `details`: one per element, at most MaxFindings.
	// FindingsTruncated reports that more elements failed.
	Findings          []Finding
	FindingsTruncated bool

	// Waived lists the forEach elements an exception waived, each naming
	// the exception. Reported even when the rule passed, so a waiver is
	// never silent. At most MaxFindings.
	Waived []Finding

	// Evaluation metadata
	Priority *int
	Category string
	Tags     []string

	// If this rule caused fail-fast termination
	CausedTermination bool
}

// MaxFindings caps the findings reported for one rule, so a forEach over a
// large input cannot grow a response without bound.
const MaxFindings = 100

// Finding is one failing forEach element: where it is in the input, and the
// values the rule's `details` selected from it.
type Finding struct {
	// Path is the element's input path, e.g. "risk_files[3]" or
	// "spec.containers[1].ports[0]" for a nested forEach.
	Path string
	// Index is the element's position in its list.
	Index int
	// Details maps each `details` name to the value its path resolved to.
	// Names whose path did not resolve are left out.
	Details map[string]any
	// Exception names the exception that waived the element (Waived only).
	Exception string
}

// Metrics contains performance metrics.
type Metrics struct {
	EvaluationTimeNs  int64
	PoliciesEvaluated int
	RulesEvaluated    int
}

// ValidationError represents a policy validation error. The JSON tags define
// the /v1/validate wire format consumed by internal/client.
type ValidationError struct {
	Message  string `json:"message"`
	Code     string `json:"code,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Filename string `json:"filename,omitempty"`
}
