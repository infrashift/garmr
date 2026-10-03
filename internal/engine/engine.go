// internal/engine/engine.go
// Package engine provides the core policy evaluation engine. Policies are
// authored in CUE, validated against the embedded schema and compiled once at
// load into Go evaluation trees; evaluation itself never touches CUE.
package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/observability"
	"github.com/infrashift/garmr/schemas"
)

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
	// loadMu serializes every policy mutation end to end: a mutation builds
	// a new set from the current one and publishes it, and two concurrent
	// mutations would otherwise each publish a set missing the other's
	// change.
	loadMu sync.Mutex

	// set is the live, immutable policy set. Evaluations load it once and
	// use it without locking; mutations publish a replacement.
	set atomic.Pointer[policySet]

	logger *zap.Logger

	// Builtins for function evaluation
	builtins map[string]BuiltinFunc

	// obs provides optional metrics, tracing, and audit logging.
	// Atomic because SetObservability is called after construction while
	// Evaluate reads it from request goroutines.
	obs atomic.Pointer[observability.Provider]

	// requireMatch controls fail-closed behavior: when true, evaluations
	// that match zero policies return DecisionDeny with a synthetic result
	// instead of the default DecisionAllow.
	requireMatch atomic.Bool
}

// policySet is an immutable snapshot of the loaded policies. It is never
// modified after publication, so any number of evaluations can read it
// concurrently.
type policySet struct {
	policies map[string]*CompiledPolicy // by namespace/name
	all      []*CompiledPolicy          // sorted by namespace/name

	// byKind indexes policies whose every selector names a concrete kind
	// (lower-cased); wildcard holds the rest. Both are sorted by key, so the
	// candidates for an input are a merge of two sorted lists.
	byKind   map[string][]*CompiledPolicy
	wildcard []*CompiledPolicy

	snap setSnapshot
}

// newPolicySet indexes a policy map. The map is owned by the set afterwards.
func newPolicySet(policies map[string]*CompiledPolicy) *policySet {
	s := &policySet{policies: policies, byKind: make(map[string][]*CompiledPolicy)}
	keys := make([]string, 0, len(policies))
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := policies[k]
		s.all = append(s.all, p)
		kinds, ok := concreteKinds(p.Target)
		if !ok {
			s.wildcard = append(s.wildcard, p)
			continue
		}
		for _, kind := range kinds {
			s.byKind[kind] = append(s.byKind[kind], p)
		}
	}
	s.snap = snapshotOf(policies)
	return s
}

// concreteKinds returns the distinct lower-cased kinds a target is limited
// to, or false when some selector could match any kind.
func concreteKinds(t TargetSpec) ([]string, bool) {
	if len(t.Resources) == 0 {
		return nil, false
	}
	seen := make(map[string]bool)
	var kinds []string
	for _, rs := range t.Resources {
		if rs.Kind == "" || strings.Contains(rs.Kind, "*") {
			return nil, false
		}
		k := strings.ToLower(rs.Kind)
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	return kinds, true
}

// candidates returns, sorted by key, the policies whose target could match
// an input of the given kind.
func (s *policySet) candidates(kind string) []*CompiledPolicy {
	if len(s.byKind) == 0 {
		return s.wildcard
	}
	a, b := s.byKind[strings.ToLower(kind)], s.wildcard
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make([]*CompiledPolicy, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if a[0].key() < b[0].key() {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	return append(append(out, a...), b...)
}

// NewEngine creates a new policy engine.
func NewEngine(logger *zap.Logger) (*Engine, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	e := &Engine{
		logger:   logger,
		builtins: make(map[string]BuiltinFunc),
	}
	e.requireMatch.Store(true)
	e.set.Store(newPolicySet(map[string]*CompiledPolicy{}))
	e.obs.Store(observability.NewProvider())

	// Fail at construction, not at the first load, if the embedded schema
	// does not compile.
	if _, _, err := newLoadContext(); err != nil {
		return nil, fmt.Errorf("loading schema: %w", err)
	}

	e.registerBuiltins()

	return e, nil
}

// SetObservability sets the observability provider for the engine.
// A nil provider is ignored so observability() never returns nil.
func (e *Engine) SetObservability(obs *observability.Provider) {
	if obs == nil {
		return
	}
	e.obs.Store(obs)
}

// observability returns the current provider (never nil).
func (e *Engine) observability() *observability.Provider {
	return e.obs.Load()
}

// SetRequireMatch controls fail-closed behavior for evaluations that match
// zero policies. When true (the default), Evaluate returns DecisionDeny with
// a synthetic result that explains why nothing matched. When false, the
// legacy fail-open behavior is restored and DecisionAllow is returned.
func (e *Engine) SetRequireMatch(v bool) {
	e.requireMatch.Store(v)
}

// policySchemaSource is the canonical policy schema, embedded from
// schemas/policy.cue so the engine, `garmr validate`, and `cue vet` cannot
// drift apart.
var policySchemaSource = schemas.PolicyCUE

// registerBuiltins registers built-in functions.
func (e *Engine) registerBuiltins() {
	e.builtins["len"] = builtinLen
	e.builtins["lower"] = builtinLower
	e.builtins["upper"] = builtinUpper
	e.builtins["matches"] = builtinMatches
	e.builtins["now"] = builtinNow

	// Register extended builtins (aggregates, CIDR, K8s units, etc.)
	e.registerExtendedBuiltins()
}
