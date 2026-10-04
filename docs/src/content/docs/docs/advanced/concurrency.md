---
title: "Concurrency Model"
description: "How Garmr handles concurrent policy evaluation"
sidebar:
  order: 2
  label: "Concurrency"
---

## Architecture

Garmr uses CUE only at load time. Evaluation runs against compiled Go data structures, reads the loaded policy set without taking a lock, and runs fully in parallel. Nothing limits it: there is no context pool, no replica cap, and no queue.

### Load: CUE to Go

When a policy loads (at server startup or on reload), the engine:

1. Unifies the policy with the embedded schema (`schemas/policy.cue`), which rejects unknown fields, typos, and wrong types.
2. Hashes it (this feeds the policy-set digest).
3. Decodes it into Go structs.
4. Compiles each rule's `expr` into a Go evaluation tree. Regexes written in the policy, semver and datetime literals, and literal sets for `in`/`notIn` are compiled up front.

A fresh CUE context is created for each load and thrown away after it. Evaluation never touches CUE.

### Engine Structure

```go
type Engine struct {
    loadMu sync.Mutex                  // serializes load / reload / delete
    set    atomic.Pointer[policySet]   // live, immutable policy set

    logger       *zap.Logger
    builtins     map[string]BuiltinFunc
    obs          atomic.Pointer[observability.Provider]
    requireMatch atomic.Bool
}
```

A `policySet` is an immutable snapshot of the loaded policies. It indexes policies by target kind, so an input is checked only against policies that could match its `kind` (plus policies whose selectors use a wildcard kind). It also holds the precomputed policy-set digest.

### Snapshot Swapping

- `Evaluate()` loads the current set once through the atomic pointer and uses that set for the whole evaluation. It takes no lock, so any number of evaluations run at the same time.
- Load, reload, and delete take `loadMu`, build a **new** set from the current one, and publish it with one atomic store. Two mutations can't run at once, so one can't drop the other's change.
- In-flight evaluations finish against the set they started with. A reload never blocks them.
- A failed load publishes nothing. The previous set stays live.
- Readiness and digest reads (`PolicyCount`, `PolicySetDigest`) also read the current set without locking.

### Backpressure

`Evaluate` returns `ErrEvaluationUnavailable` (HTTP 503) only when the caller's context has already ended before work starts, for example because the client disconnected or its deadline passed. Garmr has no evaluation slots to run out of.

## Rule Evaluation

Each request's input is normalized to JSON shape (maps, slices, `float64`, strings, bools, nil) once. Then the candidate policies are evaluated one after another, and the rules within each policy run in order:

```go
ec := &evalCtx{ctx: ctx, done: ctx.Done(), root: input}
for _, rule := range policy.Rules {
    if !shouldEvaluateRule(rule, policy.Evaluation) {
        continue
    }
    if ctx.Err() != nil { // policy timeout: deny, never a silent pass
        out.timedOut = true
        return out
    }
    result := e.evaluateRule(ec, policy, rule)
    out.results = append(out.results, result)

    if policy.Evaluation.FailFast && !result.Passed {
        out.failFast = true
        return out
    }
}
```

Running rules in order is correct and keeps fail-fast semantics. Concurrency comes from running requests in parallel, not from splitting one request across goroutines.

## Caching

### Regex Pattern Cache

Patterns written as literals in a policy are compiled at load. Patterns known only at evaluation time go into a bounded LRU cache (1024 entries, patterns up to 512 characters). These are patterns from a `compare` `matches` whose right-hand side is an input path, the `matches` builtin, and wildcard selector patterns. Because the cache is bounded, a client can't grow server memory without limit by sending new patterns.

## Performance Characteristics

The engine benchmarks (`internal/engine/bench_test.go`, plus `BenchmarkForEach_LargeInput` in `internal/engine/expr_test.go` for the `forEach` row) run the same scenarios as an OPA v1.21.1 `rego.PreparedEvalQuery` harness in `scripts/bench-opa`. Both are in-process, with the policy compiled up front. Measured on an i7-9700K:

| Scenario | Garmr | OPA |
|----------|-------|-----|
| Simple 3-rule policy | 3.0µs, 6 allocs | 24.6µs, 166 allocs |
| Simple policy, parallel | 0.49µs | 5.7µs |
| 500 policies loaded | 1.9µs | 15.9µs |
| `forEach` over 50 elements, 200-key input | 16.5µs | 461µs |

These numbers measure the engine only. HTTP handling, JSON decoding, and audit logging come on top of them.

## Benchmarking

```bash
# Engine benchmarks
go test ./internal/engine -run '^$' -bench 'BenchmarkEvaluate|BenchmarkForEach' -benchmem

# OPA comparison (separate module, so OPA is never a Garmr dependency)
cd scripts/bench-opa && go test -run '^$' -bench . -benchmem

# HTTP benchmarking with hey
go install github.com/rakyll/hey@latest

hey -n 10000 -c 100 -m POST \
    -H "Content-Type: application/json" \
    -D input.json \
    http://localhost:8080/v1/evaluate
```

## Future Optimizations

- **Result caching**: an LRU cache with a TTL for repeated inputs, which are common in admission control
