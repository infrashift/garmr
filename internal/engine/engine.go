// internal/engine/engine.go
// Package engine provides the core CUE-based policy evaluation engine.
package engine

import (
	"context"
	"fmt"
	"sync"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/observability"
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
