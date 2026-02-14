// internal/engine/engine.go
// Package engine provides the core CUE-based policy evaluation engine.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/observability"
)

// Common errors
var (
	ErrPolicyNotFound    = errors.New("policy not found")
	ErrInvalidPolicy     = errors.New("invalid policy")
	ErrInvalidInput      = errors.New("invalid input")
	ErrEvaluationFailed  = errors.New("evaluation failed")
	ErrCompilationFailed = errors.New("compilation failed")
)

// cueCtxKey is a context key for passing pooled CUE contexts through the evaluation chain.
type cueCtxKey struct{}

// withCueContext stores a pooled CUE context in a Go context for use during evaluation.
func withCueContext(ctx context.Context, cueCtx *cue.Context) context.Context {
	return context.WithValue(ctx, cueCtxKey{}, cueCtx)
}

// getCueContext retrieves the pooled CUE context from a Go context.
// Falls back to the engine's shared context if not set (for backwards compatibility).
func (e *Engine) getCueContext(ctx context.Context) *cue.Context {
	if cc, ok := ctx.Value(cueCtxKey{}).(*cue.Context); ok {
		return cc
	}
	return e.ctx
}

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

// Engine is the core policy evaluation engine.
type Engine struct {
	mu       sync.RWMutex
	ctx      *cue.Context // used only for schema/init operations under write lock
	ctxPool  *cueContextPool
	policies map[string]*CompiledPolicy
	data     cue.Value
	schema   cue.Value
	logger   *zap.Logger

	// Builtins for function evaluation
	builtins map[string]BuiltinFunc

	// regexCache caches compiled regular expressions for pattern matching
	regexCache sync.Map // map[string]*regexp.Regexp

	// obs provides optional metrics, tracing, and audit logging
	obs *observability.Provider
}

// cueContextPool provides a pool of CUE contexts for concurrent use.
// cue.Context is not documented as thread-safe, so each concurrent evaluation
// borrows its own context from the pool and returns it when done.
type cueContextPool struct {
	pool sync.Pool
}

// newCueContextPool creates a new CUE context pool.
func newCueContextPool() *cueContextPool {
	return &cueContextPool{
		pool: sync.Pool{
			New: func() any {
				return cuecontext.New()
			},
		},
	}
}

// get borrows a CUE context from the pool. Callers must call put() when done.
func (p *cueContextPool) get() *cue.Context {
	return p.pool.Get().(*cue.Context)
}

// put returns a CUE context to the pool for reuse.
func (p *cueContextPool) put(ctx *cue.Context) {
	p.pool.Put(ctx)
}

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

// BuiltinFunc is a function that can be called from policy expressions.
type BuiltinFunc func(ctx context.Context, args ...any) (any, error)

// NewEngine creates a new policy engine.
func NewEngine(logger *zap.Logger) (*Engine, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	ctx := cuecontext.New()

	e := &Engine{
		ctx:      ctx,
		ctxPool:  newCueContextPool(),
		policies: make(map[string]*CompiledPolicy),
		logger:   logger,
		builtins: make(map[string]BuiltinFunc),
		obs:      observability.NewProvider(),
	}

	// Register built-in functions
	e.registerBuiltins()

	// Load the policy schema
	if err := e.loadSchema(); err != nil {
		return nil, fmt.Errorf("loading schema: %w", err)
	}

	return e, nil
}

// SetObservability sets the observability provider for the engine.
func (e *Engine) SetObservability(obs *observability.Provider) {
	e.obs = obs
}

// loadSchema loads the embedded policy schema.
func (e *Engine) loadSchema() error {
	// Schema is embedded or loaded from filesystem
	schemaSource := `
package policy

#Policy: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: #Metadata
	spec: #PolicySpec
}

#Metadata: {
	name: string
	namespace: string | *"default"
	labels: [string]: string
	annotations: [string]: string
	...
}

#PolicySpec: {
	description?: string
	target: #Target
	rules: [#Rule, ...#Rule]
	enforcement: #Enforcement
	requires?: [..._]
	evaluation?: #EvaluationConfig
}

#EvaluationConfig: {
	order?: string | *"priority"
	failFast?: bool | *false
	includeCategories?: [...string]
	excludeCategories?: [...string]
	includeTags?: [...string]
	excludeTags?: [...string]
	maxRules?: int | *0
	timeout?: string
}

#Target: {
	resources: [...#ResourceSelector]
	conditions?: [..._]
}

#ResourceSelector: {
	apiGroup: string | *"*"
	kind: string | *"*"
	names?: [...string]
	labels?: [string]: string
	annotations?: [string]: string
	namespaces?: [...string]
}

#Rule: {
	id: string
	description: string
	severity: "critical" | "high" | "medium" | "low" | "info"
	priority?: int
	expr: _
	message?: string
	url?: string
	remediation?: string
	category?: string
	tags?: [...string]
	continueOnFail?: bool | *true
}

#Enforcement: {
	action: "deny" | "warn" | "audit"
	dryRun: bool | *false
	exceptions?: [...#Exception]
	webhook?: _
}

#Exception: {
	name: string
	reason: string
	match: #ResourceSelector
	expiry?: string
	approvedBy?: [...string]
	ticket?: string
}
`
	e.schema = e.ctx.CompileString(schemaSource)
	if e.schema.Err() != nil {
		return fmt.Errorf("compiling schema: %w", e.schema.Err())
	}

	return nil
}

// registerBuiltins registers built-in functions.
func (e *Engine) registerBuiltins() {
	e.builtins["len"] = builtinLen
	e.builtins["count"] = builtinLen
	e.builtins["lower"] = builtinLower
	e.builtins["upper"] = builtinUpper
	e.builtins["contains"] = builtinContains
	e.builtins["startsWith"] = builtinStartsWith
	e.builtins["endsWith"] = builtinEndsWith
	e.builtins["matches"] = builtinMatches
	e.builtins["now"] = builtinNow

	// Register extended builtins (aggregates, CIDR, K8s units, etc.)
	e.registerExtendedBuiltins()
}

// LoadPolicy loads and compiles a policy from CUE source.
func (e *Engine) LoadPolicy(ctx context.Context, name, namespace, source string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	start := time.Now()

	// Compile the source
	val := e.ctx.CompileString(source)
	if val.Err() != nil {
		e.obs.Metrics().RecordPolicyLoadError(name, namespace, "compilation")
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, val.Err())
	}

	// Unify with schema to validate
	unified := val.Unify(e.schema.LookupPath(cue.ParsePath("#Policy")))
	if unified.Err() != nil {
		e.obs.Metrics().RecordPolicyLoadError(name, namespace, "compilation")
		return fmt.Errorf("%w: schema validation failed: %v", ErrInvalidPolicy, unified.Err())
	}

	// Extract compiled policy
	compiled, err := e.compilePolicy(unified, name, namespace)
	if err != nil {
		e.obs.Metrics().RecordPolicyLoadError(name, namespace, "compilation")
		return fmt.Errorf("compiling policy: %w", err)
	}

	compiled.LoadedAt = time.Now()

	// Compute hash
	h := sha256.Sum256([]byte(source))
	compiled.Hash = hex.EncodeToString(h[:])

	key := policyKey(namespace, name)
	e.policies[key] = compiled

	e.logger.Info("policy loaded",
		zap.String("name", name),
		zap.String("namespace", namespace),
		zap.Int("rules", len(compiled.Rules)),
		zap.Duration("compile_time", time.Since(start)),
	)

	// Record successful policy load count for this namespace
	count := 0
	for _, p := range e.policies {
		if p.Namespace == namespace {
			count++
		}
	}
	e.obs.Metrics().SetPoliciesLoaded(namespace, count)

	return nil
}

// compilePolicy extracts a CompiledPolicy from a validated CUE value.
func (e *Engine) compilePolicy(val cue.Value, name, namespace string) (*CompiledPolicy, error) {
	cp := &CompiledPolicy{
		Name:      name,
		Namespace: namespace,
		Value:     val,
		// Default evaluation config
		Evaluation: EvaluationConfig{
			Order:    EvalOrderPriority, // Default to priority-based ordering
			FailFast: false,
		},
	}

	// Extract target
	targetVal := val.LookupPath(cue.ParsePath("spec.target"))
	if targetVal.Exists() {
		target, err := e.extractTarget(targetVal)
		if err != nil {
			return nil, fmt.Errorf("extracting target: %w", err)
		}
		cp.Target = target
	}

	// Extract evaluation config (optional)
	evalVal := val.LookupPath(cue.ParsePath("spec.evaluation"))
	if evalVal.Exists() {
		evalConfig, err := e.extractEvaluationConfig(evalVal)
		if err != nil {
			return nil, fmt.Errorf("extracting evaluation config: %w", err)
		}
		cp.Evaluation = evalConfig
	}

	// Extract rules
	rulesVal := val.LookupPath(cue.ParsePath("spec.rules"))
	if rulesVal.Exists() {
		iter, err := rulesVal.List()
		if err != nil {
			return nil, fmt.Errorf("iterating rules: %w", err)
		}

		definitionOrder := 0
		for iter.Next() {
			rule, err := e.extractRule(iter.Value())
			if err != nil {
				return nil, fmt.Errorf("extracting rule: %w", err)
			}
			// Set definition order for stable sorting
			rule.DefinitionOrder = definitionOrder
			definitionOrder++
			cp.Rules = append(cp.Rules, rule)
		}
	}

	// Sort rules according to evaluation order
	cp.Rules = sortRules(cp.Rules, cp.Evaluation.Order)

	// Extract enforcement
	enfVal := val.LookupPath(cue.ParsePath("spec.enforcement"))
	if enfVal.Exists() {
		enf, err := e.extractEnforcement(enfVal)
		if err != nil {
			return nil, fmt.Errorf("extracting enforcement: %w", err)
		}
		cp.Enforcement = enf
	}

	return cp, nil
}

// extractEvaluationConfig extracts evaluation configuration from CUE value.
func (e *Engine) extractEvaluationConfig(val cue.Value) (EvaluationConfig, error) {
	config := EvaluationConfig{
		Order:    EvalOrderPriority, // Default
		FailFast: false,
	}

	if v := val.LookupPath(cue.ParsePath("order")); v.Exists() {
		orderStr, _ := v.String()
		config.Order = EvaluationOrder(orderStr)
	}

	if v := val.LookupPath(cue.ParsePath("failFast")); v.Exists() {
		config.FailFast, _ = v.Bool()
	}

	if v := val.LookupPath(cue.ParsePath("maxRules")); v.Exists() {
		mr, _ := v.Int64()
		config.MaxRules = int(mr)
	}

	if v := val.LookupPath(cue.ParsePath("timeout")); v.Exists() {
		ts, _ := v.String()
		if d, err := time.ParseDuration(ts); err == nil {
			config.Timeout = d
		}
	}

	// Extract include/exclude categories
	if v := val.LookupPath(cue.ParsePath("includeCategories")); v.Exists() {
		config.IncludeCategories = extractStringList(v)
	}
	if v := val.LookupPath(cue.ParsePath("excludeCategories")); v.Exists() {
		config.ExcludeCategories = extractStringList(v)
	}

	// Extract include/exclude tags
	if v := val.LookupPath(cue.ParsePath("includeTags")); v.Exists() {
		config.IncludeTags = extractStringList(v)
	}
	if v := val.LookupPath(cue.ParsePath("excludeTags")); v.Exists() {
		config.ExcludeTags = extractStringList(v)
	}

	return config, nil
}

// extractStringList extracts a list of strings from a CUE value.
func extractStringList(val cue.Value) []string {
	var result []string
	iter, err := val.List()
	if err != nil {
		return result
	}
	for iter.Next() {
		if s, err := iter.Value().String(); err == nil {
			result = append(result, s)
		}
	}
	return result
}

// sortRules sorts rules according to the specified evaluation order.
func sortRules(rules []CompiledRule, order EvaluationOrder) []CompiledRule {
	if len(rules) == 0 {
		return rules
	}

	// Make a copy to avoid modifying the original slice order reference
	sorted := make([]CompiledRule, len(rules))
	copy(sorted, rules)

	switch order {
	case EvalOrderDefinition:
		// Already in definition order, no sorting needed
		return sorted

	case EvalOrderSeverity:
		// Sort by severity (critical first), then definition order
		sortBySeverityThenDefinition(sorted)

	case EvalOrderPriority:
		// Sort by priority (lower first), then definition order
		sortByPriorityThenDefinition(sorted)

	case EvalOrderPriorityThenSev:
		// Sort by priority, then severity within same priority
		sortByPriorityThenSeverity(sorted)

	default:
		// Default to priority ordering
		sortByPriorityThenDefinition(sorted)
	}

	return sorted
}

// sortByPriorityThenDefinition sorts rules by priority (lower first),
// then by definition order for rules without priority or with same priority.
func sortByPriorityThenDefinition(rules []CompiledRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return shouldSwapPriority(rules[j], rules[i])
	})
}

// shouldSwapPriority returns true if rule b should come before rule a.
func shouldSwapPriority(a, b CompiledRule) bool {
	// Rules with priority come before rules without
	if a.Priority == nil && b.Priority != nil {
		return true
	}
	if a.Priority != nil && b.Priority == nil {
		return false
	}
	// Both have priority: lower priority value comes first
	if a.Priority != nil && b.Priority != nil {
		if *a.Priority != *b.Priority {
			return *b.Priority < *a.Priority
		}
	}
	// Same priority (or both nil): maintain definition order
	return b.DefinitionOrder < a.DefinitionOrder
}

// sortBySeverityThenDefinition sorts rules by severity (critical first),
// then by definition order for same severity.
func sortBySeverityThenDefinition(rules []CompiledRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return shouldSwapSeverity(rules[j], rules[i])
	})
}

// shouldSwapSeverity returns true if rule b should come before rule a.
func shouldSwapSeverity(a, b CompiledRule) bool {
	aWeight := a.Severity.Weight()
	bWeight := b.Severity.Weight()
	if aWeight != bWeight {
		return bWeight > aWeight // Higher weight (more severe) comes first
	}
	return b.DefinitionOrder < a.DefinitionOrder
}

// sortByPriorityThenSeverity sorts by priority first, then severity within same priority.
func sortByPriorityThenSeverity(rules []CompiledRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return shouldSwapPriorityThenSeverity(rules[j], rules[i])
	})
}

// shouldSwapPriorityThenSeverity returns true if rule b should come before rule a.
func shouldSwapPriorityThenSeverity(a, b CompiledRule) bool {
	// First compare by priority
	if a.Priority == nil && b.Priority != nil {
		return true
	}
	if a.Priority != nil && b.Priority == nil {
		return false
	}
	if a.Priority != nil && b.Priority != nil {
		if *a.Priority != *b.Priority {
			return *b.Priority < *a.Priority
		}
	}
	// Same priority: compare by severity
	aWeight := a.Severity.Weight()
	bWeight := b.Severity.Weight()
	if aWeight != bWeight {
		return bWeight > aWeight
	}
	// Same priority and severity: maintain definition order
	return b.DefinitionOrder < a.DefinitionOrder
}

func (e *Engine) extractTarget(val cue.Value) (TargetSpec, error) {
	var target TargetSpec

	resourcesVal := val.LookupPath(cue.ParsePath("resources"))
	if resourcesVal.Exists() {
		iter, err := resourcesVal.List()
		if err != nil {
			return target, err
		}

		for iter.Next() {
			itemVal := iter.Value()

			// Check if it's a simple string (kind name) or structured selector
			if itemVal.Kind() == cue.StringKind {
				// Simple string format: "pod", "deployment", "*"
				kindStr, _ := itemVal.String()
				rs := ResourceSelector{Kind: kindStr}
				target.Resources = append(target.Resources, rs)
			} else {
				// Structured format: {kind: "pod", apiGroup: "v1", ...}
				rs, err := e.extractResourceSelector(itemVal)
				if err != nil {
					return target, err
				}
				target.Resources = append(target.Resources, rs)
			}
		}
	}

	return target, nil
}

func (e *Engine) extractResourceSelector(val cue.Value) (ResourceSelector, error) {
	var rs ResourceSelector

	if v := val.LookupPath(cue.ParsePath("apiGroup")); v.Exists() {
		s, _ := v.String()
		rs.APIGroup = s
	}

	if v := val.LookupPath(cue.ParsePath("kind")); v.Exists() {
		s, _ := v.String()
		rs.Kind = s
	}

	if v := val.LookupPath(cue.ParsePath("names")); v.Exists() {
		iter, _ := v.List()
		for iter.Next() {
			s, _ := iter.Value().String()
			rs.Names = append(rs.Names, s)
		}
	}

	if v := val.LookupPath(cue.ParsePath("labels")); v.Exists() {
		rs.Labels = make(map[string]string)
		iter, _ := v.Fields()
		for iter.Next() {
			s, _ := iter.Value().String()
			rs.Labels[iter.Selector().String()] = s
		}
	}

	return rs, nil
}

func (e *Engine) extractRule(val cue.Value) (CompiledRule, error) {
	var rule CompiledRule

	if v := val.LookupPath(cue.ParsePath("id")); v.Exists() {
		rule.ID, _ = v.String()
	}

	if v := val.LookupPath(cue.ParsePath("description")); v.Exists() {
		rule.Description, _ = v.String()
	}

	if v := val.LookupPath(cue.ParsePath("severity")); v.Exists() {
		s, _ := v.String()
		rule.Severity = Severity(s)
	}

	if v := val.LookupPath(cue.ParsePath("message")); v.Exists() {
		rule.Message, _ = v.String()
	}

	// Extract priority (optional)
	if v := val.LookupPath(cue.ParsePath("priority")); v.Exists() {
		p, err := v.Int64()
		if err == nil {
			pi := int(p)
			rule.Priority = &pi
		}
	}

	// Extract remediation (optional)
	if v := val.LookupPath(cue.ParsePath("remediation")); v.Exists() {
		rule.Remediation, _ = v.String()
	}

	// Extract category (optional)
	if v := val.LookupPath(cue.ParsePath("category")); v.Exists() {
		rule.Category, _ = v.String()
	}

	// Extract tags (optional)
	if v := val.LookupPath(cue.ParsePath("tags")); v.Exists() {
		iter, err := v.List()
		if err == nil {
			for iter.Next() {
				if tag, err := iter.Value().String(); err == nil {
					rule.Tags = append(rule.Tags, tag)
				}
			}
		}
	}

	// Extract continueOnFail (default: true)
	rule.ContinueOnFail = true
	if v := val.LookupPath(cue.ParsePath("continueOnFail")); v.Exists() {
		rule.ContinueOnFail, _ = v.Bool()
	}

	rule.Expression = val.LookupPath(cue.ParsePath("expr"))

	return rule, nil
}

func (e *Engine) extractEnforcement(val cue.Value) (EnforcementSpec, error) {
	var enf EnforcementSpec

	if v := val.LookupPath(cue.ParsePath("action")); v.Exists() {
		enf.Action, _ = v.String()
	}

	if v := val.LookupPath(cue.ParsePath("dryRun")); v.Exists() {
		enf.DryRun, _ = v.Bool()
	}

	// Extract exceptions
	if exceptionsVal := val.LookupPath(cue.ParsePath("exceptions")); exceptionsVal.Exists() {
		iter, _ := exceptionsVal.List()
		for iter.Next() {
			excVal := iter.Value()
			var exc ExceptionSpec
			// extract name, reason, match fields, expiry
			if v := excVal.LookupPath(cue.ParsePath("name")); v.Exists() {
				exc.Name, _ = v.String()
			}
			if v := excVal.LookupPath(cue.ParsePath("reason")); v.Exists() {
				exc.Reason, _ = v.String()
			}
			// extract match (ResourceSelector)
			if matchVal := excVal.LookupPath(cue.ParsePath("match")); matchVal.Exists() {
				rs, err := e.extractResourceSelector(matchVal)
				if err == nil {
					exc.Match = rs
				}
			}
			// extract expiry
			if v := excVal.LookupPath(cue.ParsePath("expiry")); v.Exists() {
				if expiryStr, err := v.String(); err == nil {
					if t, err := time.Parse(time.RFC3339, expiryStr); err == nil {
						exc.Expiry = &t
					}
				}
			}
			enf.Exceptions = append(enf.Exceptions, exc)
		}
	}

	return enf, nil
}

// Evaluate evaluates input against loaded policies.
func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Track active evaluations for metrics
	e.obs.Metrics().IncActiveEvaluations()
	defer e.obs.Metrics().DecActiveEvaluations()

	// Borrow a CUE context from the pool for this evaluation.
	// This ensures each concurrent evaluation has its own context,
	// avoiding thread-safety issues with shared cue.Context usage.
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	// Store the pooled CUE context in the Go context so all downstream
	// evaluation methods can access it without signature changes.
	ctx = withCueContext(ctx, cueCtx)

	start := time.Now()
	resp := &EvaluateResponse{
		Decision: DecisionAllow,
		Metrics:  &Metrics{},
	}

	if req.Options.Trace {
		resp.Trace = []TraceEvent{}
	}

	// Convert input to CUE value using pooled context
	inputVal := cueCtx.Encode(req.Input)
	if inputVal.Err() != nil {
		return nil, fmt.Errorf("%w: encoding input: %v", ErrInvalidInput, inputVal.Err())
	}

	// Find applicable policies
	policies := e.findApplicablePolicies(req)
	resp.Metrics.PoliciesEvaluated = len(policies)

	// Timeout enforcement: find the minimum timeout across all policies
	minTimeout := time.Duration(0)
	for _, p := range policies {
		if p.Evaluation.Timeout > 0 {
			if minTimeout == 0 || p.Evaluation.Timeout < minTimeout {
				minTimeout = p.Evaluation.Timeout
			}
		}
	}
	if minTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, minTimeout)
		defer cancel()
	}

	// Count total rules in scope for fail-fast metadata
	totalRulesInScope := 0
	for _, p := range policies {
		totalRulesInScope += len(p.Rules)
	}
	rulesEvaluated := 0

	// Evaluate each policy
	for _, policy := range policies {
		results, failFastTriggered, err := e.evaluatePolicy(ctx, policy, inputVal, req)
		if err != nil {
			e.logger.Error("policy evaluation failed",
				zap.String("policy", policy.Name),
				zap.Error(err),
			)
			continue
		}

		rulesEvaluated += len(results)
		resp.Metrics.RulesEvaluated += len(results)

		// Determine dry run mode
		isDryRun := false
		if req.Options.DryRunOverride != nil {
			isDryRun = *req.Options.DryRunOverride
		} else {
			isDryRun = policy.Enforcement.DryRun
		}

		for _, result := range results {
			if !result.Passed {
				// Record violation metric
				e.obs.Metrics().RecordViolation(policy.Name, policy.Namespace, result.RuleID, string(result.Severity))

				// Update decision based on severity and enforcement
				switch policy.Enforcement.Action {
				case "deny":
					resp.Decision = DecisionDeny
				case "warn":
					if resp.Decision != DecisionDeny {
						resp.Decision = DecisionWarn
					}
				}

				// Dry run: downgrade deny to warn and annotate the message
				if isDryRun {
					if resp.Decision == DecisionDeny {
						resp.Decision = DecisionWarn
					}
					result.Message = "[DRY RUN] " + result.Message
				}
			}

			// Include result based on options
			if !result.Passed || req.Options.IncludePassed {
				resp.Results = append(resp.Results, result)
			}
		}

		// Set dry run mode info
		if isDryRun {
			resp.EvaluationMode.DryRun = true
		}

		// Handle fail-fast termination
		if failFastTriggered {
			// Find the last failed result
			var lastFailed *RuleResult
			for i := len(results) - 1; i >= 0; i-- {
				if !results[i].Passed {
					r := results[i]
					r.CausedTermination = true
					lastFailed = &r
					break
				}
			}

			resp.TerminatedEarly = true
			resp.TerminationRule = lastFailed
			resp.EvaluationMode.FailFast = true
			resp.EvaluationMode.ShortCircuited = true
			resp.EvaluationMode.TotalRulesInScope = totalRulesInScope
			resp.EvaluationMode.RulesEvaluated = rulesEvaluated
			resp.EvaluationMode.RulesSkipped = totalRulesInScope - rulesEvaluated
			break
		}
	}

	resp.Metrics.EvaluationTimeNs = time.Since(start).Nanoseconds()

	// Record evaluation metric
	e.obs.Metrics().RecordEvaluation(
		"",                       // policy name (we evaluate multiple)
		req.Namespace,            // namespace
		string(resp.Decision),    // decision
		"",                       // environment
		time.Since(start),        // duration
	)

	return resp, nil
}

// findApplicablePolicies returns policies that match the request.
func (e *Engine) findApplicablePolicies(req *EvaluateRequest) []*CompiledPolicy {
	var result []*CompiledPolicy

	// If specific policies requested, return only those
	if len(req.Policies) > 0 {
		for _, name := range req.Policies {
			ns := req.Namespace
			if ns == "" {
				ns = "default"
			}
			key := policyKey(ns, name)
			if p, ok := e.policies[key]; ok {
				if e.policyMatchesInput(p, req.Input) {
					result = append(result, p)
				}
			}
		}
		return result
	}

	// Otherwise, return all policies in namespace that match the input
	for _, p := range e.policies {
		if req.Namespace == "" || p.Namespace == req.Namespace {
			if e.policyMatchesInput(p, req.Input) {
				result = append(result, p)
			}
		}
	}

	return result
}

// policyMatchesInput checks if a policy's target matches the input resource.
func (e *Engine) policyMatchesInput(policy *CompiledPolicy, input map[string]any) bool {
	// If no target resources defined, policy applies to everything
	if len(policy.Target.Resources) == 0 {
		return true
	}

	// Extract resource identifiers from input
	inputKind := getStringField(input, "kind")
	inputAPIGroup := getStringField(input, "apiVersion")
	inputName := getStringField(input, "metadata", "name")
	inputNamespace := getStringField(input, "metadata", "namespace")
	inputLabels := getMapField(input, "metadata", "labels")

	// Check if any target selector matches
	for _, selector := range policy.Target.Resources {
		if e.selectorMatchesInput(selector, inputKind, inputAPIGroup, inputName, inputNamespace, inputLabels) {
			return true
		}
	}

	return false
}

// selectorMatchesInput checks if a resource selector matches the input.
func (e *Engine) selectorMatchesInput(selector ResourceSelector, kind, apiGroup, name, namespace string, labels map[string]string) bool {
	// Check Kind (supports wildcards)
	if selector.Kind != "" && selector.Kind != "*" {
		if !e.matchesPatternCached(selector.Kind, kind) {
			return false
		}
	}

	// Check APIGroup
	if selector.APIGroup != "" && selector.APIGroup != "*" {
		if !e.matchesPatternCached(selector.APIGroup, apiGroup) {
			return false
		}
	}

	// Check Names (if specified, name must be in the list)
	if len(selector.Names) > 0 {
		found := false
		for _, n := range selector.Names {
			if e.matchesPatternCached(n, name) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check Namespaces (if specified, namespace must be in the list)
	if len(selector.Namespaces) > 0 {
		found := false
		for _, ns := range selector.Namespaces {
			if e.matchesPatternCached(ns, namespace) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check Labels (all specified labels must match)
	if len(selector.Labels) > 0 {
		for k, v := range selector.Labels {
			if labelVal, ok := labels[k]; !ok || !e.matchesPatternCached(v, labelVal) {
				return false
			}
		}
	}

	return true
}

// getCompiledRegex returns a compiled regex from the cache, compiling and caching it if needed.
func (e *Engine) getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := e.regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	e.regexCache.Store(pattern, re)
	return re, nil
}

// matchesPattern checks if a value matches a pattern (supports * wildcard).
// This is a package-level function that does not use the regex cache.
// Prefer (e *Engine).matchesPatternCached when an engine instance is available.
func matchesPattern(pattern, value string) bool {
	// Case-insensitive comparison
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Exact match
	if pattern == value {
		return true
	}

	// Wildcard matching
	if strings.Contains(pattern, "*") {
		// Convert glob pattern to regex
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}

	return false
}

// matchesPatternCached checks if a value matches a pattern using the engine's regex cache.
func (e *Engine) matchesPatternCached(pattern, value string) bool {
	// Case-insensitive comparison
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Exact match
	if pattern == value {
		return true
	}

	// Wildcard matching
	if strings.Contains(pattern, "*") {
		// Convert glob pattern to regex
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		re, err := e.getCompiledRegex(regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}

	return false
}

// getStringField safely extracts a string field from nested maps.
func getStringField(m map[string]any, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - get the value
			if val, ok := current[key]; ok {
				if s, ok := val.(string); ok {
					return s
				}
			}
			return ""
		}
		// Navigate deeper
		if next, ok := current[key]; ok {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return ""
			}
		} else {
			return ""
		}
	}
	return ""
}

// getMapField safely extracts a map field from nested maps.
func getMapField(m map[string]any, keys ...string) map[string]string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - get the map
			if val, ok := current[key]; ok {
				if mapVal, ok := val.(map[string]any); ok {
					result := make(map[string]string)
					for k, v := range mapVal {
						if s, ok := v.(string); ok {
							result[k] = s
						}
					}
					return result
				}
			}
			return nil
		}
		// Navigate deeper
		if next, ok := current[key]; ok {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return nil
			}
		} else {
			return nil
		}
	}
	return nil
}

// evaluatePolicy evaluates a single policy against input.
// Returns results, whether fail-fast was triggered, and any error.
func (e *Engine) evaluatePolicy(ctx context.Context, policy *CompiledPolicy, input cue.Value, req *EvaluateRequest) ([]RuleResult, bool, error) {
	var results []RuleResult
	opts := req.Options

	// Check if any exception matches the input, skip evaluation if so
	if len(policy.Enforcement.Exceptions) > 0 {
		if e.matchesException(policy.Enforcement.Exceptions, req.Input) {
			return results, false, nil
		}
	}

	for _, rule := range policy.Rules {
		// Category/tag filtering: skip rules that don't match filters
		if !e.shouldEvaluateRule(rule, policy.Evaluation, opts) {
			continue
		}

		// Timeout check: if the context has been cancelled/timed out, stop evaluating
		if ctx.Err() != nil {
			result := RuleResult{
				PolicyName:      policy.Name,
				PolicyNamespace: policy.Namespace,
				RuleID:          rule.ID,
				RuleDescription: rule.Description,
				Severity:        rule.Severity,
				Passed:          true, // don't penalize on timeout
				Message:         "evaluation timed out",
				Bindings:        make(map[string]any),
			}
			results = append(results, result)
			break
		}

		result := e.evaluateRule(ctx, policy, rule, input, opts)
		results = append(results, result)

		// Fail-fast: stop at first failure if configured
		if policy.Evaluation.FailFast && !result.Passed {
			return results, true, nil
		}
	}

	return results, false, nil
}

// evaluateRule evaluates a single rule against input.
func (e *Engine) evaluateRule(ctx context.Context, policy *CompiledPolicy, rule CompiledRule, input cue.Value, opts EvaluateOptions) RuleResult {
	result := RuleResult{
		PolicyName:      policy.Name,
		PolicyNamespace: policy.Namespace,
		RuleID:          rule.ID,
		RuleDescription: rule.Description,
		Severity:        rule.Severity,
		Passed:          true,
		Bindings:        make(map[string]any),
	}

	// Timeout check at rule level
	if ctx.Err() != nil {
		result.Passed = true // don't penalize on timeout
		result.Message = "evaluation timed out"
		return result
	}

	// Evaluate the expression by unifying with input
	passed, bindings, msg := e.evaluateExpression(ctx, rule.Expression, input)
	result.Passed = passed
	result.Bindings = bindings

	if !passed {
		if rule.Message != "" {
			result.Message = e.interpolateMessage(rule.Message, bindings)
		} else if msg != "" {
			result.Message = msg
		} else {
			result.Message = fmt.Sprintf("Rule %s failed: %s", rule.ID, rule.Description)
		}
	}

	return result
}

// shouldEvaluateRule returns false if the rule should be skipped based on category/tag filters.
// Both policy-level and request-level filters are applied (both must pass).
func (e *Engine) shouldEvaluateRule(rule CompiledRule, policyConfig EvaluationConfig, opts EvaluateOptions) bool {
	// Check policy-level category filters
	if len(policyConfig.IncludeCategories) > 0 {
		if !stringInSlice(rule.Category, policyConfig.IncludeCategories) {
			return false
		}
	}
	if len(policyConfig.ExcludeCategories) > 0 {
		if stringInSlice(rule.Category, policyConfig.ExcludeCategories) {
			return false
		}
	}

	// Check policy-level tag filters
	if len(policyConfig.IncludeTags) > 0 {
		if !anyTagMatches(rule.Tags, policyConfig.IncludeTags) {
			return false
		}
	}
	if len(policyConfig.ExcludeTags) > 0 {
		if anyTagMatches(rule.Tags, policyConfig.ExcludeTags) {
			return false
		}
	}

	// Check request-level category filters
	if len(opts.IncludeCategories) > 0 {
		if !stringInSlice(rule.Category, opts.IncludeCategories) {
			return false
		}
	}
	if len(opts.ExcludeCategories) > 0 {
		if stringInSlice(rule.Category, opts.ExcludeCategories) {
			return false
		}
	}

	// Check request-level tag filters
	if len(opts.IncludeTags) > 0 {
		if !anyTagMatches(rule.Tags, opts.IncludeTags) {
			return false
		}
	}
	if len(opts.ExcludeTags) > 0 {
		if anyTagMatches(rule.Tags, opts.ExcludeTags) {
			return false
		}
	}

	return true
}

// stringInSlice checks if a string is in a slice.
func stringInSlice(s string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// anyTagMatches checks if any of the rule's tags match any of the filter tags.
func anyTagMatches(ruleTags, filterTags []string) bool {
	for _, rt := range ruleTags {
		for _, ft := range filterTags {
			if strings.EqualFold(rt, ft) {
				return true
			}
		}
	}
	return false
}

// matchesException checks if any non-expired exception matches the input.
func (e *Engine) matchesException(exceptions []ExceptionSpec, input map[string]any) bool {
	inputKind := getStringField(input, "kind")
	inputAPIGroup := getStringField(input, "apiVersion")
	inputName := getStringField(input, "metadata", "name")
	inputNamespace := getStringField(input, "metadata", "namespace")
	inputLabels := getMapField(input, "metadata", "labels")

	for _, exc := range exceptions {
		// Check if exception has expired
		if exc.Expiry != nil && time.Now().After(*exc.Expiry) {
			continue
		}

		// Check if the exception's match selector applies to this input
		if e.selectorMatchesInput(exc.Match, inputKind, inputAPIGroup, inputName, inputNamespace, inputLabels) {
			return true
		}
	}

	return false
}

// valuesEqual performs type-aware comparison of two values, handling numeric type coercion.
func valuesEqual(a, b any) bool {
	// Try numeric comparison first
	aFloat, aIsNum := toFloatOk(a)
	bFloat, bIsNum := toFloatOk(b)
	if aIsNum && bIsNum {
		return aFloat == bFloat
	}

	// Fall back to string comparison
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// toFloatOk attempts to convert a value to float64, returning whether the conversion succeeded.
func toFloatOk(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	case int16:
		return float64(val), true
	case int8:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint64:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint16:
		return float64(val), true
	case uint8:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// evaluateExpression evaluates a CUE expression against input.
func (e *Engine) evaluateExpression(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	// Check for 'forEach' (array iteration)
	if forEachVal := expr.LookupPath(cue.ParsePath("forEach")); forEachVal.Exists() {
		return e.evaluateForEach(ctx, forEachVal, input)
	}

	// Check for 'all' (AND)
	if allVal := expr.LookupPath(cue.ParsePath("all")); allVal.Exists() {
		iter, _ := allVal.List()
		for iter.Next() {
			passed, b, msg := e.evaluateExpression(ctx, iter.Value(), input)
			for k, v := range b {
				bindings[k] = v
			}
			if !passed {
				return false, bindings, msg
			}
		}
		return true, bindings, ""
	}

	// Check for 'any' (OR)
	if anyVal := expr.LookupPath(cue.ParsePath("any")); anyVal.Exists() {
		iter, _ := anyVal.List()
		var lastMsg string
		for iter.Next() {
			passed, b, msg := e.evaluateExpression(ctx, iter.Value(), input)
			if passed {
				for k, v := range b {
					bindings[k] = v
				}
				return true, bindings, ""
			}
			lastMsg = msg
		}
		return false, bindings, lastMsg
	}

	// Check for 'not'
	if notVal := expr.LookupPath(cue.ParsePath("not")); notVal.Exists() {
		passed, b, _ := e.evaluateExpression(ctx, notVal, input)
		for k, v := range b {
			bindings[k] = v
		}
		return !passed, bindings, ""
	}

	// Check for 'exists'
	if existsVal := expr.LookupPath(cue.ParsePath("exists")); existsVal.Exists() {
		path, _ := existsVal.String()
		fieldVal := input.LookupPath(cue.ParsePath(path))
		exists := fieldVal.Exists() && fieldVal.Kind() != cue.NullKind
		if !exists {
			return false, bindings, fmt.Sprintf("field '%s' does not exist", path)
		}
		return true, bindings, ""
	}

	// Check for 'absent'
	if absentVal := expr.LookupPath(cue.ParsePath("absent")); absentVal.Exists() {
		path, _ := absentVal.String()
		fieldVal := input.LookupPath(cue.ParsePath(path))
		absent := !fieldVal.Exists() || fieldVal.Kind() == cue.NullKind
		if !absent {
			return false, bindings, fmt.Sprintf("field '%s' should not exist", path)
		}
		return true, bindings, ""
	}

	// Check for 'contains' (collection contains check)
	if containsVal := expr.LookupPath(cue.ParsePath("contains")); containsVal.Exists() {
		return e.evaluateContainsExpr(containsVal, input)
	}

	// Check for 'match'
	if matchVal := expr.LookupPath(cue.ParsePath("match")); matchVal.Exists() {
		return e.evaluateMatch(matchVal, input)
	}

	// Check for 'compare'
	if compareVal := expr.LookupPath(cue.ParsePath("compare")); compareVal.Exists() {
		return e.evaluateCompare(compareVal, input)
	}

	// Check for 'func' (builtin function call)
	if funcVal := expr.LookupPath(cue.ParsePath("func")); funcVal.Exists() {
		return e.evaluateFunc(ctx, funcVal, input)
	}

	// Check for 'ref' (reference to another policy's result)
	if refVal := expr.LookupPath(cue.ParsePath("ref")); refVal.Exists() {
		// ref is a forward-looking feature; currently passes (no-op)
		// Future: look up referenced policy/rule result
		return true, bindings, ""
	}

	// Default: try to unify and check for errors
	unified := input.Unify(expr)
	if unified.Err() != nil {
		return false, bindings, unified.Err().Error()
	}

	return true, bindings, ""
}

// evaluateFunc evaluates a builtin function call expression.
func (e *Engine) evaluateFunc(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	// Get function name
	nameVal := expr.LookupPath(cue.ParsePath("name"))
	if !nameVal.Exists() {
		return false, bindings, "func requires 'name'"
	}
	name, _ := nameVal.String()

	// Look up the builtin
	fn, ok := e.builtins[name]
	if !ok {
		return false, bindings, fmt.Sprintf("unknown builtin function: %s", name)
	}

	// Resolve arguments
	argsVal := expr.LookupPath(cue.ParsePath("args"))
	var args []any
	if argsVal.Exists() {
		iter, _ := argsVal.List()
		for iter.Next() {
			arg := iter.Value()
			// If it's a string that looks like an input path reference (starts with "input.")
			if s, err := arg.String(); err == nil && strings.HasPrefix(s, "input.") {
				// Resolve from input
				path := strings.TrimPrefix(s, "input.")
				resolved := input.LookupPath(cue.ParsePath(path))
				if resolved.Exists() {
					var v any
					if err := resolved.Decode(&v); err == nil {
						args = append(args, v)
						continue
					}
				}
				// If resolution fails, use the string literal
				args = append(args, s)
			} else {
				// Decode the literal value
				var v any
				if err := arg.Decode(&v); err == nil {
					args = append(args, v)
				} else {
					args = append(args, nil)
				}
			}
		}
	}

	// Call the builtin
	result, err := fn(ctx, args...)
	if err != nil {
		return false, bindings, fmt.Sprintf("builtin %s failed: %v", name, err)
	}

	// Bind result if requested
	bindVal := expr.LookupPath(cue.ParsePath("bind"))
	if bindVal.Exists() {
		bindName, _ := bindVal.String()
		if bindName != "" {
			bindings[bindName] = result
		}
	}

	// Check expectation if present
	expectVal := expr.LookupPath(cue.ParsePath("expect"))
	if expectVal.Exists() {
		var expected any
		expectVal.Decode(&expected)

		// Compare result with expected value
		if valuesEqual(result, expected) {
			return true, bindings, ""
		}
		return false, bindings, fmt.Sprintf("builtin %s returned %v, expected %v", name, result, expected)
	}

	// If no expectation, treat truthy result as pass
	// boolean true, non-zero number, non-empty string = pass
	switch v := result.(type) {
	case bool:
		if !v {
			return false, bindings, fmt.Sprintf("builtin %s returned false", name)
		}
	case nil:
		return false, bindings, fmt.Sprintf("builtin %s returned nil", name)
	}

	return true, bindings, ""
}

// evaluateMatch evaluates a match expression.
func (e *Engine) evaluateMatch(expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	pathVal := expr.LookupPath(cue.ParsePath("path"))
	if !pathVal.Exists() {
		return false, bindings, "match requires 'path'"
	}
	path, _ := pathVal.String()

	// Get value at path
	fieldVal := input.LookupPath(cue.ParsePath(path))

	// Check for 'exists' condition
	if existsVal := expr.LookupPath(cue.ParsePath("exists")); existsVal.Exists() {
		shouldExist, _ := existsVal.Bool()
		exists := fieldVal.Exists() && fieldVal.Kind() != cue.NullKind
		if shouldExist && !exists {
			return false, bindings, fmt.Sprintf("field '%s' does not exist", path)
		}
		if !shouldExist && exists {
			return false, bindings, fmt.Sprintf("field '%s' should not exist", path)
		}
		return true, bindings, ""
	}

	// Check for 'pattern' (regex match)
	if patternVal := expr.LookupPath(cue.ParsePath("pattern")); patternVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		pattern, _ := patternVal.String()
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid pattern: %s", err)
		}

		if !re.MatchString(fieldStr) {
			return false, bindings, fmt.Sprintf("'%s' does not match pattern '%s'", fieldStr, pattern)
		}
		return true, bindings, ""
	}

	// Check for 'equals' (exact match)
	if equalsVal := expr.LookupPath(cue.ParsePath("equals")); equalsVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual interface{}
		equalsVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if !valuesEqual(actual, expected) {
			return false, bindings, fmt.Sprintf("'%s' expected '%v', got '%v'", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'greaterThan'
	if gtVal := expr.LookupPath(cue.ParsePath("greaterThan")); gtVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		gtVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual <= expected {
			return false, bindings, fmt.Sprintf("'%s' expected > %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'greaterThanOrEqual'
	if gteVal := expr.LookupPath(cue.ParsePath("greaterThanOrEqual")); gteVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		gteVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual < expected {
			return false, bindings, fmt.Sprintf("'%s' expected >= %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'lessThan'
	if ltVal := expr.LookupPath(cue.ParsePath("lessThan")); ltVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		ltVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual >= expected {
			return false, bindings, fmt.Sprintf("'%s' expected < %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'lessThanOrEqual'
	if lteVal := expr.LookupPath(cue.ParsePath("lessThanOrEqual")); lteVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		lteVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual > expected {
			return false, bindings, fmt.Sprintf("'%s' expected <= %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'in' (value in list)
	if inVal := expr.LookupPath(cue.ParsePath("in")); inVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var actual interface{}
		fieldVal.Decode(&actual)

		iter, err := inVal.List()
		if err != nil {
			return false, bindings, "'in' must be a list"
		}

		found := false
		var allowedValues []string
		for iter.Next() {
			var v interface{}
			iter.Value().Decode(&v)
			allowedValues = append(allowedValues, fmt.Sprintf("%v", v))
			if valuesEqual(actual, v) {
				found = true
				break
			}
		}

		if !found {
			return false, bindings, fmt.Sprintf("'%s' value '%v' not in allowed list %v", path, actual, allowedValues)
		}
		return true, bindings, ""
	}

	// Check for 'notIn' (value not in list)
	if notInVal := expr.LookupPath(cue.ParsePath("notIn")); notInVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var actual interface{}
		fieldVal.Decode(&actual)

		iter, err := notInVal.List()
		if err != nil {
			return false, bindings, "'notIn' must be a list"
		}

		for iter.Next() {
			var v interface{}
			iter.Value().Decode(&v)
			if valuesEqual(actual, v) {
				return false, bindings, fmt.Sprintf("'%s' value '%v' is in forbidden list", path, actual)
			}
		}
		return true, bindings, ""
	}

	// Check for 'contains' (string contains)
	if containsVal := expr.LookupPath(cue.ParsePath("contains")); containsVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		substr, _ := containsVal.String()
		if !strings.Contains(fieldStr, substr) {
			return false, bindings, fmt.Sprintf("'%s' does not contain '%s'", path, substr)
		}
		return true, bindings, ""
	}

	// Check for 'hasPrefix'
	if prefixVal := expr.LookupPath(cue.ParsePath("hasPrefix")); prefixVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		prefix, _ := prefixVal.String()
		if !strings.HasPrefix(fieldStr, prefix) {
			return false, bindings, fmt.Sprintf("'%s' does not have prefix '%s'", path, prefix)
		}
		return true, bindings, ""
	}

	// Check for 'hasSuffix'
	if suffixVal := expr.LookupPath(cue.ParsePath("hasSuffix")); suffixVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		suffix, _ := suffixVal.String()
		if !strings.HasSuffix(fieldStr, suffix) {
			return false, bindings, fmt.Sprintf("'%s' does not have suffix '%s'", path, suffix)
		}
		return true, bindings, ""
	}

	// Check for 'length' conditions (array or string length)
	if lengthVal := expr.LookupPath(cue.ParsePath("length")); lengthVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}
		return e.evaluateLength(fieldVal, lengthVal, path)
	}

	// Check for 'semver' (semantic version comparison)
	if semverVal := expr.LookupPath(cue.ParsePath("semver")); semverVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}
		return e.evaluateSemver(fieldVal, semverVal, path)
	}

	// Check for 'datetime' (date/time comparison)
	if datetimeVal := expr.LookupPath(cue.ParsePath("datetime")); datetimeVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}
		return e.evaluateDatetime(fieldVal, datetimeVal, path)
	}

	return false, bindings, "match requires one of: exists, pattern, equals, greaterThan, lessThan, in, notIn, contains, hasPrefix, hasSuffix, length, semver, datetime"
}

// evaluateCompare evaluates a compare expression.
func (e *Engine) evaluateCompare(expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	leftVal := expr.LookupPath(cue.ParsePath("left"))
	opVal := expr.LookupPath(cue.ParsePath("op"))
	rightVal := expr.LookupPath(cue.ParsePath("right"))

	if !leftVal.Exists() || !opVal.Exists() || !rightVal.Exists() {
		return false, bindings, "compare requires 'left', 'op', and 'right'"
	}

	left := e.resolveValue(leftVal, input)
	op, _ := opVal.String()
	right := e.resolveValue(rightVal, input)

	result := e.compare(left, op, right)
	if !result {
		return false, bindings, fmt.Sprintf("comparison failed: %v %s %v", left, op, right)
	}

	return true, bindings, ""
}

// resolveValue resolves a Value to an actual value.
func (e *Engine) resolveValue(val cue.Value, input cue.Value) any {
	// Check for literal
	if litVal := val.LookupPath(cue.ParsePath("literal")); litVal.Exists() {
		var v any
		litVal.Decode(&v)
		return v
	}

	// Check for path reference
	if pathVal := val.LookupPath(cue.ParsePath("path")); pathVal.Exists() {
		path, _ := pathVal.String()
		fieldVal := input.LookupPath(cue.ParsePath(path))
		if fieldVal.Exists() {
			var v any
			fieldVal.Decode(&v)
			return v
		}
		return nil
	}

	// Check for func call
	if funcVal := val.LookupPath(cue.ParsePath("func")); funcVal.Exists() {
		nameVal := funcVal.LookupPath(cue.ParsePath("name"))
		if !nameVal.Exists() {
			return nil
		}
		name, _ := nameVal.String()
		fn, ok := e.builtins[name]
		if !ok {
			return nil
		}

		// Resolve arguments
		argsVal := funcVal.LookupPath(cue.ParsePath("args"))
		var args []any
		if argsVal.Exists() {
			iter, _ := argsVal.List()
			for iter.Next() {
				resolved := e.resolveValue(iter.Value(), input)
				args = append(args, resolved)
			}
		}

		result, err := fn(context.Background(), args...)
		if err != nil {
			return nil
		}
		return result
	}

	// Check for env variable
	if envVal := val.LookupPath(cue.ParsePath("env")); envVal.Exists() {
		envName, _ := envVal.String()
		return os.Getenv(envName)
	}

	return nil
}

// compare performs comparison operation.
func (e *Engine) compare(left any, op string, right any) bool {
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	switch op {
	case "==", "eq":
		return valuesEqual(left, right)
	case "!=", "ne", "neq":
		return !valuesEqual(left, right)
	case ">", "gt":
		return toFloat(left) > toFloat(right)
	case ">=", "gte":
		return toFloat(left) >= toFloat(right)
	case "<", "lt":
		return toFloat(left) < toFloat(right)
	case "<=", "lte":
		return toFloat(left) <= toFloat(right)
	case "in":
		if arr, ok := right.([]any); ok {
			for _, v := range arr {
				if valuesEqual(left, v) {
					return true
				}
			}
		}
		return false
	case "not_in", "notIn":
		if arr, ok := right.([]any); ok {
			for _, v := range arr {
				if valuesEqual(left, v) {
					return false
				}
			}
		}
		return true
	case "contains":
		return strings.Contains(leftStr, rightStr)
	case "hasPrefix", "startsWith":
		return strings.HasPrefix(leftStr, rightStr)
	case "hasSuffix", "endsWith":
		return strings.HasSuffix(leftStr, rightStr)
	case "matches":
		re, err := regexp.Compile(rightStr)
		if err != nil {
			return false
		}
		return re.MatchString(leftStr)
	// Semantic version comparisons
	case "semverGt":
		return compareSemver(leftStr, rightStr) > 0
	case "semverGte":
		return compareSemver(leftStr, rightStr) >= 0
	case "semverLt":
		return compareSemver(leftStr, rightStr) < 0
	case "semverLte":
		return compareSemver(leftStr, rightStr) <= 0
	case "semverEq":
		return compareSemver(leftStr, rightStr) == 0
	// Datetime comparisons
	case "after":
		return compareDatetime(leftStr, rightStr) > 0
	case "before":
		return compareDatetime(leftStr, rightStr) < 0
	case "afterOrEqual":
		return compareDatetime(leftStr, rightStr) >= 0
	case "beforeOrEqual":
		return compareDatetime(leftStr, rightStr) <= 0
	}
	return false
}

// toFloat converts a value to float64 for numeric comparison
func toFloat(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case int32:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	default:
		return 0
	}
}

// evaluateForEach evaluates a forEach expression against an array in input.
// forEach iterates over an array and applies a condition to each element.
// Syntax: forEach: { path: "spec.containers", as: "container", condition: { match: {...} } }
func (e *Engine) evaluateForEach(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	pathVal := expr.LookupPath(cue.ParsePath("path"))
	if !pathVal.Exists() {
		return false, bindings, "forEach requires 'path'"
	}
	path, _ := pathVal.String()

	// Get the array at path
	arrayVal := input.LookupPath(cue.ParsePath(path))
	if !arrayVal.Exists() {
		return false, bindings, fmt.Sprintf("path '%s' not found", path)
	}

	// Check if it's a list
	iter, err := arrayVal.List()
	if err != nil {
		return false, bindings, fmt.Sprintf("path '%s' is not an array", path)
	}

	// Get the alias for the current element (default: "item")
	alias := "item"
	if asVal := expr.LookupPath(cue.ParsePath("as")); asVal.Exists() {
		alias, _ = asVal.String()
	}

	// Get the condition to apply to each element
	conditionVal := expr.LookupPath(cue.ParsePath("condition"))
	if !conditionVal.Exists() {
		return false, bindings, "forEach requires 'condition'"
	}

	// Check for mode: "all" (default) or "any"
	mode := "all"
	if modeVal := expr.LookupPath(cue.ParsePath("mode")); modeVal.Exists() {
		mode, _ = modeVal.String()
	}

	// Iterate over the array
	index := 0
	var failedItems []string
	anyPassed := false

	for iter.Next() {
		itemVal := iter.Value()

		// Create a new input context with the current item aliased
		// We need to merge the item into the input under the alias
		itemInput := e.createItemContext(ctx, input, itemVal, alias, index)

		passed, b, msg := e.evaluateExpression(ctx, conditionVal, itemInput)
		for k, v := range b {
			bindings[k] = v
		}

		if mode == "all" && !passed {
			failedItems = append(failedItems, fmt.Sprintf("%s[%d]: %s", path, index, msg))
		}

		if mode == "any" && passed {
			anyPassed = true
		}

		index++
	}

	// Empty array handling
	if index == 0 {
		// Check if empty arrays should pass or fail
		if allowEmptyVal := expr.LookupPath(cue.ParsePath("allowEmpty")); allowEmptyVal.Exists() {
			allowEmpty, _ := allowEmptyVal.Bool()
			if !allowEmpty {
				return false, bindings, fmt.Sprintf("path '%s' is an empty array", path)
			}
		}
		return true, bindings, ""
	}

	if mode == "all" {
		if len(failedItems) > 0 {
			return false, bindings, strings.Join(failedItems, "; ")
		}
		return true, bindings, ""
	}

	// mode == "any"
	if anyPassed {
		return true, bindings, ""
	}
	return false, bindings, fmt.Sprintf("no items in '%s' matched the condition", path)
}

// createItemContext creates a new CUE value context with the item aliased.
// Uses the pooled CUE context from the Go context for thread safety.
func (e *Engine) createItemContext(ctx context.Context, input cue.Value, item cue.Value, alias string, index int) cue.Value {
	// Decode original input
	var inputMap map[string]any
	input.Decode(&inputMap)
	if inputMap == nil {
		inputMap = make(map[string]any)
	}

	// Decode item
	var itemData any
	item.Decode(&itemData)

	// Add item under alias
	inputMap[alias] = itemData
	inputMap["_index"] = index

	// Rebuild CUE value using pooled context
	return e.getCueContext(ctx).Encode(inputMap)
}

// evaluateContainsExpr evaluates a standalone contains expression.
// Checks if a collection at the given path contains specific values.
//
//	contains: { path: "spec.tags", value: "production" }             // single value
//	contains: { path: "spec.tags", all: ["production", "reviewed"] } // all must be present
//	contains: { path: "spec.tags", any: ["staging", "production"] }  // at least one
func (e *Engine) evaluateContainsExpr(expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	pathVal := expr.LookupPath(cue.ParsePath("path"))
	if !pathVal.Exists() {
		return false, bindings, "contains requires 'path'"
	}
	path, _ := pathVal.String()

	fieldVal := input.LookupPath(cue.ParsePath(path))
	if !fieldVal.Exists() {
		return false, bindings, fmt.Sprintf("path '%s' not found", path)
	}

	// Decode the collection
	var collection []any
	if err := fieldVal.Decode(&collection); err != nil {
		// Try as string contains
		if s, sErr := fieldVal.String(); sErr == nil {
			// Single value check on string
			if checkVal := expr.LookupPath(cue.ParsePath("value")); checkVal.Exists() {
				var needle string
				checkVal.Decode(&needle)
				if strings.Contains(s, needle) {
					return true, bindings, ""
				}
				return false, bindings, fmt.Sprintf("'%s' does not contain '%s'", path, needle)
			}
		}
		return false, bindings, fmt.Sprintf("path '%s' is not a collection", path)
	}

	// Single value check
	if checkVal := expr.LookupPath(cue.ParsePath("value")); checkVal.Exists() {
		var needle any
		checkVal.Decode(&needle)
		for _, item := range collection {
			if valuesEqual(item, needle) {
				return true, bindings, ""
			}
		}
		return false, bindings, fmt.Sprintf("'%s' does not contain %v", path, needle)
	}

	// All values must be present
	if allVal := expr.LookupPath(cue.ParsePath("all")); allVal.Exists() {
		var required []any
		allVal.Decode(&required)
		for _, needle := range required {
			found := false
			for _, item := range collection {
				if valuesEqual(item, needle) {
					found = true
					break
				}
			}
			if !found {
				return false, bindings, fmt.Sprintf("'%s' missing required value %v", path, needle)
			}
		}
		return true, bindings, ""
	}

	// Any value must be present
	if anyVal := expr.LookupPath(cue.ParsePath("any")); anyVal.Exists() {
		var candidates []any
		anyVal.Decode(&candidates)
		for _, needle := range candidates {
			for _, item := range collection {
				if valuesEqual(item, needle) {
					return true, bindings, ""
				}
			}
		}
		return false, bindings, fmt.Sprintf("'%s' contains none of the expected values", path)
	}

	return false, bindings, "contains requires 'value', 'all', or 'any'"
}

// evaluateLength evaluates length conditions on arrays or strings
func (e *Engine) evaluateLength(fieldVal cue.Value, lengthExpr cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	// Get the length of the field
	var length int
	switch fieldVal.Kind() {
	case cue.ListKind:
		iter, _ := fieldVal.List()
		for iter.Next() {
			length++
		}
	case cue.StringKind:
		s, _ := fieldVal.String()
		length = len(s)
	default:
		return false, bindings, fmt.Sprintf("'%s' is not an array or string", path)
	}

	bindings["length"] = length

	// Check various length conditions
	if eqVal := lengthExpr.LookupPath(cue.ParsePath("equals")); eqVal.Exists() {
		expected, _ := eqVal.Int64()
		if int64(length) != expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if gtVal := lengthExpr.LookupPath(cue.ParsePath("greaterThan")); gtVal.Exists() {
		expected, _ := gtVal.Int64()
		if int64(length) <= expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected > %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if gteVal := lengthExpr.LookupPath(cue.ParsePath("greaterThanOrEqual")); gteVal.Exists() {
		expected, _ := gteVal.Int64()
		if int64(length) < expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected >= %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if ltVal := lengthExpr.LookupPath(cue.ParsePath("lessThan")); ltVal.Exists() {
		expected, _ := ltVal.Int64()
		if int64(length) >= expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected < %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if lteVal := lengthExpr.LookupPath(cue.ParsePath("lessThanOrEqual")); lteVal.Exists() {
		expected, _ := lteVal.Int64()
		if int64(length) > expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected <= %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if minVal := lengthExpr.LookupPath(cue.ParsePath("min")); minVal.Exists() {
		min, _ := minVal.Int64()
		if int64(length) < min {
			return false, bindings, fmt.Sprintf("'%s' length is %d, minimum is %d", path, length, min)
		}
		// Check max too if provided
		if maxVal := lengthExpr.LookupPath(cue.ParsePath("max")); maxVal.Exists() {
			max, _ := maxVal.Int64()
			if int64(length) > max {
				return false, bindings, fmt.Sprintf("'%s' length is %d, maximum is %d", path, length, max)
			}
		}
		return true, bindings, ""
	}

	if maxVal := lengthExpr.LookupPath(cue.ParsePath("max")); maxVal.Exists() {
		max, _ := maxVal.Int64()
		if int64(length) > max {
			return false, bindings, fmt.Sprintf("'%s' length is %d, maximum is %d", path, length, max)
		}
		return true, bindings, ""
	}

	return false, bindings, "length requires one of: equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, min, max"
}

// evaluateSemver evaluates semantic version comparisons
func (e *Engine) evaluateSemver(fieldVal cue.Value, semverExpr cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	version, err := fieldVal.String()
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a string", path)
	}

	// Parse the actual version
	actualVer, err := parseSemver(version)
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a valid semver: %s", path, version)
	}
	bindings["version"] = version

	// Check various semver conditions
	if eqVal := semverExpr.LookupPath(cue.ParsePath("equals")); eqVal.Exists() {
		expected, _ := eqVal.String()
		expectedVer, err := parseSemver(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected semver: %s", expected)
		}
		if compareSemverParsed(actualVer, expectedVer) != 0 {
			return false, bindings, fmt.Sprintf("'%s' version %s != %s", path, version, expected)
		}
		return true, bindings, ""
	}

	if gtVal := semverExpr.LookupPath(cue.ParsePath("greaterThan")); gtVal.Exists() {
		expected, _ := gtVal.String()
		expectedVer, err := parseSemver(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected semver: %s", expected)
		}
		if compareSemverParsed(actualVer, expectedVer) <= 0 {
			return false, bindings, fmt.Sprintf("'%s' version %s is not > %s", path, version, expected)
		}
		return true, bindings, ""
	}

	if gteVal := semverExpr.LookupPath(cue.ParsePath("greaterThanOrEqual")); gteVal.Exists() {
		expected, _ := gteVal.String()
		expectedVer, err := parseSemver(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected semver: %s", expected)
		}
		if compareSemverParsed(actualVer, expectedVer) < 0 {
			return false, bindings, fmt.Sprintf("'%s' version %s is not >= %s", path, version, expected)
		}
		return true, bindings, ""
	}

	if ltVal := semverExpr.LookupPath(cue.ParsePath("lessThan")); ltVal.Exists() {
		expected, _ := ltVal.String()
		expectedVer, err := parseSemver(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected semver: %s", expected)
		}
		if compareSemverParsed(actualVer, expectedVer) >= 0 {
			return false, bindings, fmt.Sprintf("'%s' version %s is not < %s", path, version, expected)
		}
		return true, bindings, ""
	}

	if lteVal := semverExpr.LookupPath(cue.ParsePath("lessThanOrEqual")); lteVal.Exists() {
		expected, _ := lteVal.String()
		expectedVer, err := parseSemver(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected semver: %s", expected)
		}
		if compareSemverParsed(actualVer, expectedVer) > 0 {
			return false, bindings, fmt.Sprintf("'%s' version %s is not <= %s", path, version, expected)
		}
		return true, bindings, ""
	}

	// Check for constraint (e.g., ">=1.0.0,<2.0.0")
	if constraintVal := semverExpr.LookupPath(cue.ParsePath("constraint")); constraintVal.Exists() {
		constraint, _ := constraintVal.String()
		if !matchSemverConstraint(actualVer, constraint) {
			return false, bindings, fmt.Sprintf("'%s' version %s does not satisfy constraint %s", path, version, constraint)
		}
		return true, bindings, ""
	}

	return false, bindings, "semver requires one of: equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, constraint"
}

// semverParts holds parsed semantic version components
type semverParts struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
}

// parseSemver parses a semantic version string
func parseSemver(version string) (semverParts, error) {
	var parts semverParts

	// Remove leading 'v' if present
	version = strings.TrimPrefix(version, "v")

	// Split off build metadata
	if idx := strings.Index(version, "+"); idx >= 0 {
		parts.Build = version[idx+1:]
		version = version[:idx]
	}

	// Split off prerelease
	if idx := strings.Index(version, "-"); idx >= 0 {
		parts.Prerelease = version[idx+1:]
		version = version[:idx]
	}

	// Parse major.minor.patch
	segments := strings.Split(version, ".")

	if len(segments) >= 1 {
		parts.Major, _ = strconv.Atoi(segments[0])
	}
	if len(segments) >= 2 {
		parts.Minor, _ = strconv.Atoi(segments[1])
	}
	if len(segments) >= 3 {
		parts.Patch, _ = strconv.Atoi(segments[2])
	}

	return parts, nil
}

// compareSemverParsed compares two parsed semver versions
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func compareSemverParsed(a, b semverParts) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}

	// Prerelease comparison
	// A version with prerelease has lower precedence than one without
	if a.Prerelease == "" && b.Prerelease != "" {
		return 1
	}
	if a.Prerelease != "" && b.Prerelease == "" {
		return -1
	}
	if a.Prerelease != b.Prerelease {
		if a.Prerelease < b.Prerelease {
			return -1
		}
		return 1
	}

	return 0
}

// compareSemver compares two semver strings
func compareSemver(a, b string) int {
	aParts, _ := parseSemver(a)
	bParts, _ := parseSemver(b)
	return compareSemverParsed(aParts, bParts)
}

// matchSemverConstraint checks if a version matches a constraint like ">=1.0.0,<2.0.0"
func matchSemverConstraint(version semverParts, constraint string) bool {
	// Split constraint by comma for AND conditions
	conditions := strings.Split(constraint, ",")

	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}

		// Parse operator and version
		var op string
		var verStr string

		if strings.HasPrefix(cond, ">=") {
			op = ">="
			verStr = strings.TrimPrefix(cond, ">=")
		} else if strings.HasPrefix(cond, "<=") {
			op = "<="
			verStr = strings.TrimPrefix(cond, "<=")
		} else if strings.HasPrefix(cond, ">") {
			op = ">"
			verStr = strings.TrimPrefix(cond, ">")
		} else if strings.HasPrefix(cond, "<") {
			op = "<"
			verStr = strings.TrimPrefix(cond, "<")
		} else if strings.HasPrefix(cond, "=") {
			op = "="
			verStr = strings.TrimPrefix(cond, "=")
		} else if strings.HasPrefix(cond, "^") {
			// Caret: compatible with version (same major)
			op = "^"
			verStr = strings.TrimPrefix(cond, "^")
		} else if strings.HasPrefix(cond, "~") {
			// Tilde: patch-level changes allowed
			op = "~"
			verStr = strings.TrimPrefix(cond, "~")
		} else {
			// Assume exact match
			op = "="
			verStr = cond
		}

		constraintVer, _ := parseSemver(strings.TrimSpace(verStr))
		cmp := compareSemverParsed(version, constraintVer)

		switch op {
		case ">":
			if cmp <= 0 {
				return false
			}
		case ">=":
			if cmp < 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case "=":
			if cmp != 0 {
				return false
			}
		case "^":
			// Must be same major version and >= constraint
			if version.Major != constraintVer.Major || cmp < 0 {
				return false
			}
		case "~":
			// Must be same major.minor and >= constraint
			if version.Major != constraintVer.Major || version.Minor != constraintVer.Minor || cmp < 0 {
				return false
			}
		}
	}

	return true
}

// evaluateDatetime evaluates date/time comparisons
func (e *Engine) evaluateDatetime(fieldVal cue.Value, datetimeExpr cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	dateStr, err := fieldVal.String()
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a string", path)
	}

	// Parse the actual datetime
	actualTime, err := parseDateTime(dateStr)
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a valid datetime: %s", path, dateStr)
	}
	bindings["datetime"] = actualTime.Format(time.RFC3339)

	// Check for 'after'
	if afterVal := datetimeExpr.LookupPath(cue.ParsePath("after")); afterVal.Exists() {
		expected, _ := afterVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if !actualTime.After(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is not after %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'before'
	if beforeVal := datetimeExpr.LookupPath(cue.ParsePath("before")); beforeVal.Exists() {
		expected, _ := beforeVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if !actualTime.Before(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is not before %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'afterOrEqual'
	if afterEqVal := datetimeExpr.LookupPath(cue.ParsePath("afterOrEqual")); afterEqVal.Exists() {
		expected, _ := afterEqVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if actualTime.Before(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is before %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'beforeOrEqual'
	if beforeEqVal := datetimeExpr.LookupPath(cue.ParsePath("beforeOrEqual")); beforeEqVal.Exists() {
		expected, _ := beforeEqVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if actualTime.After(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is after %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'withinDays' (relative to now)
	if withinDaysVal := datetimeExpr.LookupPath(cue.ParsePath("withinDays")); withinDaysVal.Exists() {
		days, _ := withinDaysVal.Int64()
		deadline := time.Now().AddDate(0, 0, int(days))
		if actualTime.After(deadline) {
			return false, bindings, fmt.Sprintf("'%s' %s is more than %d days from now", path, dateStr, days)
		}
		return true, bindings, ""
	}

	// Check for 'withinHours' (relative to now)
	if withinHoursVal := datetimeExpr.LookupPath(cue.ParsePath("withinHours")); withinHoursVal.Exists() {
		hours, _ := withinHoursVal.Int64()
		deadline := time.Now().Add(time.Duration(hours) * time.Hour)
		if actualTime.After(deadline) {
			return false, bindings, fmt.Sprintf("'%s' %s is more than %d hours from now", path, dateStr, hours)
		}
		return true, bindings, ""
	}

	// Check for 'expiresAfterDays' (must be at least N days in the future)
	if expiresAfterVal := datetimeExpr.LookupPath(cue.ParsePath("expiresAfterDays")); expiresAfterVal.Exists() {
		days, _ := expiresAfterVal.Int64()
		minExpiry := time.Now().AddDate(0, 0, int(days))
		if actualTime.Before(minExpiry) {
			return false, bindings, fmt.Sprintf("'%s' %s expires in less than %d days", path, dateStr, days)
		}
		return true, bindings, ""
	}

	// Check for 'notExpired' (must be in the future)
	if notExpiredVal := datetimeExpr.LookupPath(cue.ParsePath("notExpired")); notExpiredVal.Exists() {
		shouldNotBeExpired, _ := notExpiredVal.Bool()
		isExpired := actualTime.Before(time.Now())
		if shouldNotBeExpired && isExpired {
			return false, bindings, fmt.Sprintf("'%s' %s has expired", path, dateStr)
		}
		if !shouldNotBeExpired && !isExpired {
			return false, bindings, fmt.Sprintf("'%s' %s has not expired", path, dateStr)
		}
		return true, bindings, ""
	}

	return false, bindings, "datetime requires one of: after, before, afterOrEqual, beforeOrEqual, withinDays, withinHours, expiresAfterDays, notExpired"
}

// parseDateTime parses a datetime string in various formats
func parseDateTime(s string) (time.Time, error) {
	// Handle special value "now"
	if strings.ToLower(s) == "now" {
		return time.Now(), nil
	}

	// Try various formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006",
		"02-Jan-2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse datetime: %s", s)
}

// compareDatetime compares two datetime strings
func compareDatetime(a, b string) int {
	aTime, err := parseDateTime(a)
	if err != nil {
		return 0
	}
	bTime, err := parseDateTime(b)
	if err != nil {
		return 0
	}

	if aTime.Before(bTime) {
		return -1
	}
	if aTime.After(bTime) {
		return 1
	}
	return 0
}

// interpolateMessage replaces template variables in a message.
func (e *Engine) interpolateMessage(msg string, bindings map[string]any) string {
	result := msg
	for k, v := range bindings {
		placeholder := fmt.Sprintf("{{.%s}}", k)
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", v))
	}
	return result
}

// ListPolicies returns all loaded policies.
func (e *Engine) ListPolicies(namespace string) []*CompiledPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*CompiledPolicy
	for _, p := range e.policies {
		if namespace == "" || p.Namespace == namespace {
			result = append(result, p)
		}
	}
	return result
}

// GetPolicy returns a specific policy.
func (e *Engine) GetPolicy(namespace, name string) (*CompiledPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	key := policyKey(namespace, name)
	if p, ok := e.policies[key]; ok {
		return p, nil
	}
	return nil, ErrPolicyNotFound
}

// DeletePolicy removes a policy.
func (e *Engine) DeletePolicy(namespace, name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := policyKey(namespace, name)
	if _, ok := e.policies[key]; ok {
		delete(e.policies, key)
		return true
	}
	return false
}

// ClearPolicies removes all loaded policies.
func (e *Engine) ClearPolicies() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = make(map[string]*CompiledPolicy)
	e.logger.Info("cleared all policies")
}

// ReloadPoliciesFromDir atomically reloads all policies from a directory.
// This is safe to call while evaluations are in progress - in-flight evaluations
// will complete with the old policy set, new evaluations will use the new set.
func (e *Engine) ReloadPoliciesFromDir(ctx context.Context, dir string) (int, error) {
	// Load into a new map (no lock needed during load)
	newPolicies := make(map[string]*CompiledPolicy)

	if err := e.loadPoliciesIntoMap(ctx, dir, newPolicies); err != nil {
		return 0, err
	}

	// Atomic swap - only hold lock briefly
	e.mu.Lock()
	e.policies = newPolicies
	e.mu.Unlock()

	e.logger.Info("policies reloaded atomically", zap.Int("count", len(newPolicies)))
	return len(newPolicies), nil
}

// loadPoliciesIntoMap loads policies into the provided map (no locking).
func (e *Engine) loadPoliciesIntoMap(ctx context.Context, dir string, policies map[string]*CompiledPolicy) error {
	// Load from the directory itself
	if err := e.loadSingleDirIntoMap(ctx, dir, policies); err != nil {
		e.logger.Debug("no policies in root, scanning subdirectories", zap.String("dir", dir))
	}

	// Walk subdirectories
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "cue.mod" {
			continue
		}

		subdir := filepath.Join(dir, name)

		hasCueFiles, _ := e.hasCueFiles(subdir)
		if hasCueFiles {
			if err := e.loadSingleDirIntoMap(ctx, subdir, policies); err != nil {
				e.logger.Warn("failed to load policies from subdirectory",
					zap.String("dir", subdir),
					zap.Error(err),
				)
				continue
			}
		} else {
			// Recursively check deeper
			e.loadPoliciesIntoMap(ctx, subdir, policies)
		}
	}

	return nil
}

// loadSingleDirIntoMap loads policies from a single directory into the map.
func (e *Engine) loadSingleDirIntoMap(ctx context.Context, dir string, policies map[string]*CompiledPolicy) error {
	// Use pooled context since this may be called without the engine lock
	// (e.g., from ReloadPoliciesFromDir).
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	cfg := &load.Config{
		Dir: dir,
	}

	instances := load.Instances([]string{"."}, cfg)
	loadedAny := false

	for _, inst := range instances {
		if inst.Err != nil {
			return fmt.Errorf("loading instance: %w", inst.Err)
		}

		val := cueCtx.BuildInstance(inst)
		if val.Err() != nil {
			return fmt.Errorf("building instance: %w", val.Err())
		}

		iter, _ := val.Fields()
		for iter.Next() {
			fieldVal := iter.Value()

			kindVal := fieldVal.LookupPath(cue.ParsePath("kind"))
			if !kindVal.Exists() {
				continue
			}

			kind, _ := kindVal.String()
			if kind != "Policy" {
				continue
			}

			nameVal := fieldVal.LookupPath(cue.ParsePath("metadata.name"))
			nsVal := fieldVal.LookupPath(cue.ParsePath("metadata.namespace"))

			name, _ := nameVal.String()
			ns := "default"
			if nsVal.Exists() {
				ns, _ = nsVal.String()
			}

			compiled, err := e.compilePolicy(fieldVal, name, ns)
			if err != nil {
				e.logger.Warn("skipping invalid policy",
					zap.String("name", name),
					zap.Error(err),
				)
				continue
			}

			compiled.LoadedAt = time.Now()
			key := policyKey(ns, name)
			policies[key] = compiled
			loadedAny = true

			e.logger.Info("loaded policy from directory",
				zap.String("name", name),
				zap.String("namespace", ns),
			)
		}
	}

	if !loadedAny {
		return fmt.Errorf("no policies found in %s", dir)
	}

	return nil
}

// Validate validates a policy without loading it.
func (e *Engine) Validate(source string) ([]ValidationError, []ValidationError) {
	// Use pooled context for thread-safe concurrent validation
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	val := cueCtx.CompileString(source)
	if val.Err() != nil {
		return []ValidationError{{
			Message: val.Err().Error(),
			Code:    "PARSE_ERROR",
		}}, nil
	}

	unified := val.Unify(e.schema.LookupPath(cue.ParsePath("#Policy")))
	if unified.Err() != nil {
		return []ValidationError{{
			Message: unified.Err().Error(),
			Code:    "SCHEMA_ERROR",
		}}, nil
	}

	return nil, nil
}

// ValidationError represents a policy validation error.
type ValidationError struct {
	Message  string
	Code     string
	Line     int
	Column   int
	Filename string
}

// SetData sets external data for policy evaluation.
func (e *Engine) SetData(path string, data any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	dataVal := e.ctx.Encode(data)
	if dataVal.Err() != nil {
		return fmt.Errorf("encoding data: %w", dataVal.Err())
	}

	// Merge with existing data
	if e.data.Exists() {
		e.data = e.data.FillPath(cue.ParsePath(path), dataVal)
	} else {
		e.data = dataVal
	}

	return nil
}

// GetData retrieves data at the given path.
func (e *Engine) GetData(path string) any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.data.Exists() {
		return nil
	}

	if path == "" || path == "/" {
		var result any
		e.data.Decode(&result)
		return result
	}

	val := e.data.LookupPath(cue.ParsePath(strings.TrimPrefix(path, "/")))
	if !val.Exists() {
		return nil
	}

	var result any
	val.Decode(&result)
	return result
}

// PutData sets data at the given path.
func (e *Engine) PutData(path string, data any) error {
	return e.SetData(strings.TrimPrefix(path, "/"), data)
}

// DeleteData removes data at the given path.
func (e *Engine) DeleteData(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// For simplicity, we'll just set nil at the path
	// A more complete implementation would properly remove the path
	if e.data.Exists() && path != "" && path != "/" {
		// CUE doesn't have a direct way to delete paths
		// So we rebuild data without that path
		// For now, just log that deletion is limited
	}
}

// policyKey creates a unique key for a policy.
func policyKey(namespace, name string) string {
	if namespace == "" {
		namespace = "default"
	}
	return namespace + "/" + name
}

// Built-in functions

func builtinLen(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("len requires exactly 1 argument")
	}
	switch v := args[0].(type) {
	case string:
		return len(v), nil
	case []any:
		return len(v), nil
	case map[string]any:
		return len(v), nil
	default:
		return nil, fmt.Errorf("len: unsupported type %T", args[0])
	}
}

func builtinLower(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("lower requires exactly 1 argument")
	}
	if s, ok := args[0].(string); ok {
		return strings.ToLower(s), nil
	}
	return nil, errors.New("lower: argument must be string")
}

func builtinUpper(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("upper requires exactly 1 argument")
	}
	if s, ok := args[0].(string); ok {
		return strings.ToUpper(s), nil
	}
	return nil, errors.New("upper: argument must be string")
}

func builtinContains(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("contains requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	substr, ok2 := args[1].(string)
	if ok1 && ok2 {
		return strings.Contains(s, substr), nil
	}
	return nil, errors.New("contains: arguments must be strings")
}

func builtinStartsWith(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("startsWith requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	prefix, ok2 := args[1].(string)
	if ok1 && ok2 {
		return strings.HasPrefix(s, prefix), nil
	}
	return nil, errors.New("startsWith: arguments must be strings")
}

func builtinEndsWith(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("endsWith requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	suffix, ok2 := args[1].(string)
	if ok1 && ok2 {
		return strings.HasSuffix(s, suffix), nil
	}
	return nil, errors.New("endsWith: arguments must be strings")
}

func builtinMatches(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("matches requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	pattern, ok2 := args[1].(string)
	if ok1 && ok2 {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("matches: invalid pattern: %w", err)
		}
		return re.MatchString(s), nil
	}
	return nil, errors.New("matches: arguments must be strings")
}

func builtinNow(ctx context.Context, args ...any) (any, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}

// LoadPoliciesFromDir loads all policies from a directory and its subdirectories.
func (e *Engine) LoadPoliciesFromDir(ctx context.Context, dir string) error {
	// First, try to load from the directory itself
	if err := e.loadPoliciesFromSingleDir(ctx, dir); err != nil {
		// If it fails, it might be a parent directory - try subdirectories
		e.logger.Debug("no policies in root, scanning subdirectories", zap.String("dir", dir))
	}

	// Walk subdirectories to find more policies
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Skip hidden directories and common non-policy directories
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "cue.mod" {
			continue
		}

		subdir := filepath.Join(dir, name)

		// Check if subdirectory contains .cue files
		hasCueFiles, _ := e.hasCueFiles(subdir)
		if hasCueFiles {
			if err := e.loadPoliciesFromSingleDir(ctx, subdir); err != nil {
				e.logger.Warn("failed to load policies from subdirectory",
					zap.String("dir", subdir),
					zap.Error(err),
				)
				// Continue with other directories
				continue
			}
		} else {
			// Recursively check deeper directories
			if err := e.LoadPoliciesFromDir(ctx, subdir); err != nil {
				e.logger.Debug("no policies in subdirectory", zap.String("dir", subdir))
			}
		}
	}

	return nil
}

// hasCueFiles checks if a directory contains .cue files
func (e *Engine) hasCueFiles(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cue") {
			return true, nil
		}
	}
	return false, nil
}

// loadPoliciesFromSingleDir loads policies from a single directory (non-recursive)
func (e *Engine) loadPoliciesFromSingleDir(ctx context.Context, dir string) error {
	// Use pooled context for thread safety during reload operations
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	cfg := &load.Config{
		Dir: dir,
	}

	instances := load.Instances([]string{"."}, cfg)
	loadedAny := false

	// Track namespaces that got policies loaded for metrics
	namespaceCounts := make(map[string]int)

	for _, inst := range instances {
		if inst.Err != nil {
			e.obs.Metrics().RecordPolicyLoadError("", dir, "compilation")
			return fmt.Errorf("loading instance: %w", inst.Err)
		}

		val := cueCtx.BuildInstance(inst)
		if val.Err() != nil {
			e.obs.Metrics().RecordPolicyLoadError("", dir, "compilation")
			return fmt.Errorf("building instance: %w", val.Err())
		}

		// Iterate fields to find policies
		iter, _ := val.Fields()
		for iter.Next() {
			fieldVal := iter.Value()

			// Check if this is a policy
			kindVal := fieldVal.LookupPath(cue.ParsePath("kind"))
			if !kindVal.Exists() {
				continue
			}

			kind, _ := kindVal.String()
			if kind != "Policy" {
				continue
			}

			// Extract name
			nameVal := fieldVal.LookupPath(cue.ParsePath("metadata.name"))
			nsVal := fieldVal.LookupPath(cue.ParsePath("metadata.namespace"))

			name, _ := nameVal.String()
			ns := "default"
			if nsVal.Exists() {
				ns, _ = nsVal.String()
			}

			compiled, err := e.compilePolicy(fieldVal, name, ns)
			if err != nil {
				e.obs.Metrics().RecordPolicyLoadError(name, ns, "compilation")
				e.logger.Warn("skipping invalid policy",
					zap.String("name", name),
					zap.Error(err),
				)
				continue
			}

			compiled.LoadedAt = time.Now()
			key := policyKey(ns, name)
			e.policies[key] = compiled
			loadedAny = true
			namespaceCounts[ns]++

			e.logger.Info("loaded policy from directory",
				zap.String("name", name),
				zap.String("namespace", ns),
			)
		}
	}

	if !loadedAny {
		return fmt.Errorf("no policies found in %s", dir)
	}

	// Record loaded policy counts per namespace
	for ns, count := range namespaceCounts {
		e.obs.Metrics().SetPoliciesLoaded(ns, count)
	}

	return nil
}
