---
title: "Concurrency Model"
description: "How Garmr handles concurrent policy evaluation"
sidebar:
  order: 2
  label: "Concurrency"
---

## Architecture

Garmr uses a read-write lock with a CUE context pool to support safe concurrent evaluation.

### Engine Structure

```go
type Engine struct {
    mu         sync.RWMutex
    ctx        *cue.Context       // Schema/init operations only (under write lock)
    ctxPool    *cueContextPool    // Thread-safe pool for evaluation
    policies   map[string]*CompiledPolicy
    data       cue.Value
    schema     cue.Value
    logger     *zap.Logger
    builtins   map[string]BuiltinFunc
    regexCache sync.Map           // Compiled regex pattern cache
    obs        *observability.Provider
}
```

### Locking Strategy

- `Evaluate()` -- takes **read lock** (multiple evaluations run concurrently)
- `LoadPolicy()` -- takes **write lock** (blocks evaluations during policy reload)
- Policy reloads are infrequent, so write lock contention is minimal

## CUE Context Pool

CUE contexts are not thread-safe for concurrent compilation and encoding. Garmr solves this with a `sync.Pool` that provides each concurrent evaluation its own context.

```go
type cueContextPool struct {
    pool sync.Pool
}

func newCueContextPool() *cueContextPool {
    return &cueContextPool{
        pool: sync.Pool{
            New: func() any {
                return cuecontext.New()
            },
        },
    }
}
```

### How It Works

1. Each `Evaluate()` call borrows a CUE context from the pool
2. The context is stored in the Go context for downstream access
3. Input encoding and rule evaluation use the borrowed context
4. The context is returned to the pool when evaluation completes

```go
func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
    // Borrow a CUE context from the pool
    cueCtx := e.ctxPool.get()
    defer e.ctxPool.put(cueCtx)

    // Store in Go context for downstream methods
    ctx = withCueContext(ctx, cueCtx)

    // Encode input with dedicated context (thread-safe)
    inputVal := cueCtx.Encode(req.Input)
    // ...
}
```

### Pool Sizing

The pool uses Go's `sync.Pool`, which dynamically manages its size:

- Grows automatically as concurrent demand increases
- Shrinks during garbage collection when demand is low
- No fixed upper bound -- scales with actual concurrency

This is preferable to a fixed-size channel-based pool because it adapts to load without blocking or wasting memory during low-traffic periods.

## Rule Evaluation

Rules within a policy are currently evaluated sequentially:

```go
for _, rule := range policy.Rules {
    if !e.shouldEvaluateRule(rule, policy.Evaluation, opts) {
        continue
    }
    result := e.evaluateRule(ctx, policy, rule, input, opts)
    results = append(results, result)

    // Fail-fast: stop at first failure
    if policy.Evaluation.FailFast && !result.Passed {
        return results, true, nil
    }
}
```

Sequential evaluation is correct and supports fail-fast semantics. Parallel rule evaluation is a potential future optimization for policies with many independent rules.

## Caching

### Regex Pattern Cache

Compiled regular expressions are cached in a `sync.Map` to avoid recompilation on repeated evaluations:

```go
regexCache sync.Map // map[string]*regexp.Regexp
```

This is lock-free for reads and safe for concurrent access.

## Performance Characteristics

### For a 4 CPU / 16GB VM

| Scenario | Estimated Throughput | Latency (p50) | Latency (p99) |
|----------|---------------------|---------------|---------------|
| Simple policy (5 rules) | 3,000-5,000 req/sec | 1ms | 5ms |
| Medium policy (20 rules) | 1,500-2,500 req/sec | 3ms | 15ms |
| Complex policy (50 rules) | 500-1,000 req/sec | 8ms | 40ms |

### Memory Usage

| Component | Estimate |
|-----------|----------|
| Base process | ~50MB |
| CUE contexts (pool) | ~200MB |
| Compiled policies (100) | ~100MB |
| gRPC buffers | ~200MB |
| **Total** | **~500MB-1GB** |

## Benchmarking

```bash
# HTTP benchmarking with hey
go install github.com/rakyll/hey@latest

hey -n 10000 -c 100 -m POST \
    -H "Content-Type: application/json" \
    -D input.json \
    http://localhost:8080/v1/evaluate

# gRPC benchmarking with ghz
go install github.com/bojand/ghz/cmd/ghz@latest

ghz --insecure \
    --proto api/proto/policy.proto \
    --call policy.PolicyService/Evaluate \
    -d '{"input": {...}}' \
    -n 10000 -c 100 \
    localhost:9090
```

## Future Optimizations

- **Parallel rule evaluation** -- evaluate independent rules concurrently within a policy using a worker pool
- **Result caching** -- LRU cache with TTL for repeated inputs (common in admission control scenarios)
