package engine

import (
	"context"
	"errors"
	"time"

	"cuelang.org/go/cue"
)

// Common errors
var (
	ErrPolicyNotFound    = errors.New("policy not found")
	ErrInvalidPolicy     = errors.New("invalid policy")
	ErrInvalidInput      = errors.New("invalid input")
	ErrEvaluationFailed  = errors.New("evaluation failed")
	ErrCompilationFailed = errors.New("compilation failed")
)

// Decision represents the overall evaluation decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionWarn  Decision = "warn"
)

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
	Value       cue.Value
	Rules       []CompiledRule
	Target      TargetSpec
	Enforcement EnforcementSpec
	Evaluation  EvaluationConfig
	LoadedAt    time.Time
}

// CompiledRule is a pre-compiled rule within a policy.
type CompiledRule struct {
	ID             string
	Description    string
	Severity       Severity
	Priority       *int // nil means not specified (use definition order)
	Expression     cue.Value
	Message        string
	Remediation    string
	Category       string
	Tags           []string
	ContinueOnFail bool
	// Internal: original position in the rules list for stable sorting
	DefinitionOrder int
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

// DefaultPriorities for rule categories
const (
	PriorityPromotion  = 100
	PrioritySecurity   = 200
	PriorityQuality    = 300
	PriorityCompliance = 400
	PriorityAdvisory   = 500
)

// TargetSpec defines what resources a policy applies to.
type TargetSpec struct {
	Resources  []ResourceSelector
	Conditions []cue.Value
}

// ResourceSelector identifies resources.
type ResourceSelector struct {
	APIGroup   string
	Kind       string
	Names      []string
	Labels     map[string]string
	Namespaces []string
}

// EnforcementSpec defines enforcement behavior.
type EnforcementSpec struct {
	Action     string
	DryRun     bool
	Exceptions []ExceptionSpec
}

// ExceptionSpec defines an exception to enforcement.
type ExceptionSpec struct {
	Name   string
	Reason string
	Match  ResourceSelector
	Expiry *time.Time
}

// EvaluateRequest contains the input for policy evaluation.
type EvaluateRequest struct {
	Input      map[string]any
	Policies   []string // Specific policies to evaluate (empty = all matching)
	Namespace  string   // Filter policies by namespace (empty = all namespaces)
	Namespaces []string // Multiple namespaces to include
	Options    EvaluateOptions
}

// EvaluateOptions controls evaluation behavior.
type EvaluateOptions struct {
	Trace          bool
	IncludePassed  bool
	Strict         bool
	Instrument     bool
	DryRunOverride *bool

	// Category/tag filtering (applied in addition to policy-level config)
	IncludeCategories []string
	ExcludeCategories []string
	IncludeTags       []string
	ExcludeTags       []string
}

// EvaluateResponse contains evaluation results.
type EvaluateResponse struct {
	Decision Decision
	Results  []RuleResult
	Metrics  *Metrics
	Trace    []TraceEvent

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
	// Order used for rule evaluation
	Order EvaluationOrder
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
	TotalRules  int
	Passed      int
	Failed      int
	Skipped     int
	BySeverity  map[Severity]SeverityCounts
	ByCategory  map[string]CategoryCounts
	ByNamespace map[string]NamespaceCounts
}

// SeverityCounts tracks pass/fail by severity.
type SeverityCounts struct {
	Passed int
	Failed int
}

// CategoryCounts tracks pass/fail by category.
type CategoryCounts struct {
	Passed int
	Failed int
}

// NamespaceCounts tracks pass/fail by namespace.
type NamespaceCounts struct {
	Passed int
	Failed int
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

	// Evaluation metadata
	Priority         *int
	Category         string
	Tags             []string
	EvaluationOrder  int   // Order in which this rule was evaluated
	EvaluationTimeNs int64 // Time taken to evaluate this rule

	// If this rule caused fail-fast termination
	CausedTermination bool
}

// Metrics contains performance metrics.
type Metrics struct {
	EvaluationTimeNs  int64
	PoliciesEvaluated int
	RulesEvaluated    int
	CompileTimeNs     int64
	CacheHit          bool
}

// TraceEvent captures evaluation trace information.
type TraceEvent struct {
	Timestamp time.Time
	Operation string
	Location  string
	Message   string
	Locals    map[string]any
}

// ValidationError represents a policy validation error.
type ValidationError struct {
	Message  string
	Code     string
	Line     int
	Column   int
	Filename string
}
