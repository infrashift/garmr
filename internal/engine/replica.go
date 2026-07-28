package engine

import (
	"fmt"
	"runtime"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
)

// policyReplica bundles a cue.Context with every value compiled in it: the
// schema and the compiled policy set. A cue.Context is not thread-safe and
// cue.Values must never be mixed across contexts, so the context and the
// values built in it are owned and used as a single unit by exactly one
// goroutine at a time.
type policyReplica struct {
	ctx      *cue.Context
	schema   cue.Value
	policies map[string]*CompiledPolicy
}

// policySet is a pool of identical policy replicas. Evaluations check out a
// whole replica for their duration; policy mutations either build a fresh set
// and atomically swap it in (reload) or exclusively acquire every replica and
// apply the same change to each (incremental load/delete).
type policySet struct {
	k        int
	replicas chan *policyReplica
}

// defaultReplicaCount bounds evaluation parallelism. Each replica carries a
// full compiled copy of the policy set, so the count trades memory and
// (re)load time for concurrency.
func defaultReplicaCount() int {
	k := runtime.GOMAXPROCS(0)
	if k > 8 {
		k = 8
	}
	if k < 1 {
		k = 1
	}
	return k
}

// newPolicySet creates a set of k empty replicas, each with its own context
// and schema.
func newPolicySet(k int) (*policySet, error) {
	s := &policySet{
		k:        k,
		replicas: make(chan *policyReplica, k),
	}
	for i := 0; i < k; i++ {
		r, err := newPolicyReplica()
		if err != nil {
			return nil, err
		}
		s.replicas <- r
	}
	return s, nil
}

// newPolicyReplica creates one empty replica with a fresh context and schema.
func newPolicyReplica() (*policyReplica, error) {
	ctx := cuecontext.New()
	schema := ctx.CompileString(policySchemaSource)
	if schema.Err() != nil {
		return nil, fmt.Errorf("compiling schema: %w", schema.Err())
	}
	return &policyReplica{
		ctx:      ctx,
		schema:   schema,
		policies: make(map[string]*CompiledPolicy),
	}, nil
}

// get checks a replica out of the set, blocking until one is available.
// Callers must return it with put.
func (s *policySet) get() *policyReplica {
	return <-s.replicas
}

// put returns a replica to the set.
func (s *policySet) put(r *policyReplica) {
	s.replicas <- r
}

// mutateAll applies a mutation to every replica atomically: it drains every
// replica (blocking until in-flight evaluations return theirs), runs prepare
// against each, and applies the returned commit functions only if every
// prepare succeeded.
//
// The two-phase shape matters for fallible mutations: applying as it went
// would leave replicas that already succeeded holding the mutation after a
// non-deterministic failure (transient I/O, memory pressure), and since
// evaluations check out an arbitrary replica, two identical requests could
// then return different decisions. Infallible mutations (DeletePolicy) pass
// a nil error and put the work in the commit closure.
func (s *policySet) mutateAll(prepare func(i int, r *policyReplica) (commit func(), err error)) error {
	drained := make([]*policyReplica, s.k)
	for i := 0; i < s.k; i++ {
		drained[i] = <-s.replicas
	}
	defer func() {
		for _, r := range drained {
			s.replicas <- r
		}
	}()

	commits := make([]func(), 0, s.k)
	for i, r := range drained {
		commit, err := prepare(i, r)
		if err != nil {
			// Abandon every prepared commit: no replica is mutated.
			return err
		}
		if commit != nil {
			commits = append(commits, commit)
		}
	}

	for _, commit := range commits {
		commit()
	}
	return nil
}
