// internal/engine/engine.go
// Package engine provides the core CUE-based policy evaluation engine.
package engine

import (
	"context"
	"fmt"
	"sync"

	"cuelang.org/go/cue"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/observability"
)

// cueCtxKey is a context key for passing the checked-out replica's CUE
// context through the evaluation chain.
type cueCtxKey struct{}

// withCueContext stores a replica's CUE context in a Go context for use during evaluation.
func withCueContext(ctx context.Context, cueCtx *cue.Context) context.Context {
	return context.WithValue(ctx, cueCtxKey{}, cueCtx)
}

// getCueContext retrieves the replica's CUE context from a Go context.
// Evaluate always installs it via withCueContext; any other entry point
// would mix values across CUE contexts, so fail loudly rather than
// silently producing wrong decisions.
func (e *Engine) getCueContext(ctx context.Context) *cue.Context {
	cc, ok := ctx.Value(cueCtxKey{}).(*cue.Context)
	if !ok {
		panic("engine: no CUE context on context.Context; evaluation must go through Engine.Evaluate")
	}
	return cc
}

// Reserved identifiers used for the synthetic "no policy matched" result
// and for guarding a user from loading a policy into the internal namespace.
const (
	ReservedSystemNamespace = "__system__"
	SystemPolicyNameMatch   = "policy-match"
	RuleIDNoMatch           = "no-match"
	SystemPolicyNameTimeout = "policy-timeout"
	RuleIDTimeout           = "timeout"
)

// Engine is the core policy evaluation engine.
type Engine struct {
	// mu guards set and requireMatch. Policy mutations additionally
	// serialize on it so replica sets are never modified concurrently.
	mu sync.RWMutex

	// set holds the replicated compiled policy state. Each replica owns a
	// cue.Context and every value compiled in it; evaluations check out a
	// whole replica so values from different contexts are never mixed.
	set *policySet

	logger *zap.Logger

	// Builtins for function evaluation
	builtins map[string]BuiltinFunc

	// regexCache caches compiled regular expressions for pattern matching.
	// Bounded, because patterns can come from caller-supplied input.
	regexCache *regexCache

	// obs provides optional metrics, tracing, and audit logging
	obs *observability.Provider

	// requireMatch controls fail-closed behavior: when true, evaluations
	// that match zero policies return DecisionDeny with a synthetic result
	// instead of the default DecisionAllow.
	requireMatch bool
}

// NewEngine creates a new policy engine.
func NewEngine(logger *zap.Logger) (*Engine, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	set, err := newPolicySet(defaultReplicaCount())
	if err != nil {
		return nil, fmt.Errorf("loading schema: %w", err)
	}

	e := &Engine{
		set:          set,
		logger:       logger,
		builtins:     make(map[string]BuiltinFunc),
		regexCache:   newRegexCache(maxRegexCacheEntries),
		obs:          observability.NewProvider(),
		requireMatch: true,
	}

	// Register built-in functions
	e.registerBuiltins()

	return e, nil
}

// currentSet returns the engine's active policy set.
func (e *Engine) currentSet() *policySet {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.set
}

// SetObservability sets the observability provider for the engine.
func (e *Engine) SetObservability(obs *observability.Provider) {
	e.obs = obs
}

// SetRequireMatch controls fail-closed behavior for evaluations that match
// zero policies. When true (the default), Evaluate returns DecisionDeny with
// a synthetic result that explains why nothing matched. When false, the
// legacy fail-open behavior is restored and DecisionAllow is returned.
func (e *Engine) SetRequireMatch(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requireMatch = v
}

// policySchemaSource is the embedded policy schema. Each policy replica
// compiles its own copy so schema values never cross context boundaries.
const policySchemaSource = `
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
	// A resource is either a kind shorthand ("pod", "*") or a full selector.
	resources: [...(string | #ResourceSelector)]
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
