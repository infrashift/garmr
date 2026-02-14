# Garmr - Concurrency Analysis

## Current Implementation Analysis

### Locking Strategy

```go
type Engine struct {
    mu       sync.RWMutex  // Single global lock
    ctx      *cue.Context  // Shared CUE context
    policies map[string]*CompiledPolicy
    // ...
}
```

**Current Pattern:**
- `Evaluate()` - Takes **RLock** (read lock) for entire duration
- `LoadPolicy()` - Takes **exclusive Lock** (write lock)
- Multiple evaluations can run concurrently (good)
- Policy loads block all evaluations (acceptable for infrequent operation)

### Bottlenecks Identified

| Component | Issue | Impact |
|-----------|-------|--------|
| `cue.Context` | Shared across all goroutines | CUE contexts are NOT thread-safe for concurrent compilation |
| `e.ctx.Encode()` | Called per request under RLock | Serializes input encoding |
| Sequential rule evaluation | `for _, rule := range policy.Rules` | No parallelism within policy |
| No result caching | Same input re-evaluated fully | Wasted CPU cycles |
| No connection pooling | gRPC defaults | May limit concurrent clients |

### CUE Thread Safety Issue

**Critical:** `cue.Context` is NOT safe for concurrent use when compiling/encoding.
The current implementation shares one context across all goroutines.

```go
// PROBLEM: Called concurrently under RLock
inputVal := e.ctx.Encode(req.Input)  // NOT THREAD SAFE
```

## Estimated Performance (Current Implementation)

### Assumptions for 4 CPU / 16GB VM:

| Factor | Value |
|--------|-------|
| Avg policy size | 20 rules |
| Avg rule complexity | Medium (5-10 expressions) |
| Input size | ~10KB JSON |
| CUE encode time | ~0.5ms |
| Rule evaluation time | ~0.2ms per rule |
| Total request time | ~5-10ms |

### Throughput Estimate (Current - Flawed):

Due to the shared `cue.Context` issue:
- **Actual safe concurrency: ~1-2 requests** (serialized by CUE)
- **Theoretical max: ~100-200 req/sec** (limited by CUE encoding)

This is **far below** what the hardware can handle.

---

## Future Optimization Considerations

Currently, these optimizations should be considered purely hypothetical. We will implement atomic experimental optimizations in the near future to determine the actual improvements and weight the complexity against the performance gains.

### 1. CUE Context Pool

```go
type Engine struct {
    mu          sync.RWMutex
    policies    map[string]*CompiledPolicy
    ctxPool     *CUEContextPool  // Pool of CUE contexts
    resultCache *ResultCache      // LRU cache for results
    logger      *zap.Logger
}

// CUEContextPool provides thread-safe CUE context access
type CUEContextPool struct {
    pool chan *cue.Context
    size int
}

func NewCUEContextPool(size int) *CUEContextPool {
    p := &CUEContextPool{
        pool: make(chan *cue.Context, size),
        size: size,
    }
    for i := 0; i < size; i++ {
        p.pool <- cuecontext.New()
    }
    return p
}

func (p *CUEContextPool) Get() *cue.Context {
    return <-p.pool
}

func (p *CUEContextPool) Put(ctx *cue.Context) {
    p.pool <- ctx
}
```

### 2. Parallel Rule Evaluation

```go
func (e *Engine) evaluatePolicyParallel(ctx context.Context, policy *CompiledPolicy, 
    input cue.Value, opts EvaluateOptions) ([]RuleResult, error) {
    
    rules := policy.Rules
    results := make([]RuleResult, len(rules))
    
    // Use worker pool sized to CPU count
    var wg sync.WaitGroup
    sem := make(chan struct{}, runtime.NumCPU())
    
    for i, rule := range rules {
        wg.Add(1)
        go func(idx int, r CompiledRule) {
            defer wg.Done()
            sem <- struct{}{}        // Acquire
            defer func() { <-sem }() // Release
            
            results[idx] = e.evaluateRule(ctx, policy, r, input, opts)
        }(i, rule)
    }
    
    wg.Wait()
    return results, nil
}
```

### 3. Result Caching

```go
type ResultCache struct {
    cache *lru.Cache
    mu    sync.RWMutex
    ttl   time.Duration
}

type CacheKey struct {
    PolicyHash string
    InputHash  string
}

func (e *Engine) EvaluateWithCache(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
    // Compute cache key
    inputHash := hashInput(req.Input)
    
    // Check cache first
    if cached, ok := e.resultCache.Get(inputHash, req.Policies); ok {
        return cached, nil
    }
    
    // Evaluate and cache
    resp, err := e.Evaluate(ctx, req)
    if err == nil {
        e.resultCache.Set(inputHash, req.Policies, resp, e.resultCache.ttl)
    }
    
    return resp, err
}
```

### 4. Optimized Evaluate Function

```go
func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
    start := time.Now()
    
    // Get a CUE context from pool (non-blocking if pool sized correctly)
    cueCtx := e.ctxPool.Get()
    defer e.ctxPool.Put(cueCtx)
    
    // Encode input with dedicated context
    inputVal := cueCtx.Encode(req.Input)
    if inputVal.Err() != nil {
        return nil, fmt.Errorf("%w: encoding input: %v", ErrInvalidInput, inputVal.Err())
    }
    
    // Read lock only for policy lookup
    e.mu.RLock()
    policies := e.findApplicablePolicies(req)
    e.mu.RUnlock()
    
    resp := &EvaluateResponse{
        Decision: DecisionAllow,
        Metrics:  &Metrics{PoliciesEvaluated: len(policies)},
    }
    
    // Evaluate policies in parallel if multiple
    if len(policies) > 1 {
        results := e.evaluatePoliciesParallel(ctx, policies, inputVal, req.Options)
        // Merge results...
    } else if len(policies) == 1 {
        results, _ := e.evaluatePolicyParallel(ctx, policies[0], inputVal, req.Options)
        // Process results...
    }
    
    resp.Metrics.EvaluationTimeNs = time.Since(start).Nanoseconds()
    return resp, nil
}
```

### 5. gRPC Server Tuning

```go
func (s *Server) startGRPC() error {
    opts := []grpc.ServerOption{
        grpc.MaxRecvMsgSize(16 * 1024 * 1024),
        grpc.MaxSendMsgSize(16 * 1024 * 1024),
        grpc.NumStreamWorkers(uint32(runtime.NumCPU() * 2)),
        grpc.MaxConcurrentStreams(1000),
        // Connection keepalive
        grpc.KeepaliveParams(keepalive.ServerParameters{
            MaxConnectionIdle:     5 * time.Minute,
            MaxConnectionAge:      30 * time.Minute,
            MaxConnectionAgeGrace: 5 * time.Second,
            Time:                  1 * time.Minute,
            Timeout:               20 * time.Second,
        }),
        grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
            MinTime:             30 * time.Second,
            PermitWithoutStream: true,
        }),
    }
    
    s.grpcServer = grpc.NewServer(opts...)
    // ...
}
```

---

## Optimized Performance Estimate

### For 4 CPU / 16GB / SSD VM:

| Configuration | Value |
|--------------|-------|
| CUE Context Pool Size | 8 (2x CPU) |
| Worker Pool Size | 4 (1x CPU) |
| Result Cache Size | 10,000 entries |
| Cache TTL | 60 seconds |
| gRPC Max Concurrent Streams | 1000 |

### Expected Throughput:

| Scenario | Requests/sec | Latency (p50) | Latency (p99) |
|----------|-------------|---------------|---------------|
| Simple policy (5 rules) | 3,000-5,000 | 1ms | 5ms |
| Medium policy (20 rules) | 1,500-2,500 | 3ms | 15ms |
| Complex policy (50 rules) | 500-1,000 | 8ms | 40ms |
| With caching (80% hit) | 8,000-15,000 | <1ms | 5ms |

### Memory Usage:

| Component | Estimate |
|-----------|----------|
| Base process | ~50MB |
| CUE contexts (8) | ~200MB |
| Compiled policies (100) | ~100MB |
| Result cache (10K entries) | ~500MB |
| gRPC buffers | ~200MB |
| **Total** | **~1-2GB** (well within 16GB) |

### CPU Utilization:

- At 2,000 req/sec: ~60-80% CPU utilization
- Headroom for bursts up to 3,000 req/sec

---

## Quick Wins (Low Effort, High Impact)

### 1. Fix CUE Context Thread Safety (Critical)

```go
// In NewEngine()
e.ctxPool = NewCUEContextPool(runtime.NumCPU() * 2)
```

**Impact:** Enables true concurrent evaluation. **10-50x throughput increase.**

### 2. Add Input Hash Caching

```go
// Cache expensive CUE encoding
type encodedInputCache struct {
    cache *lru.Cache  // inputHash -> cue.Value
}
```

**Impact:** 2-3x for repeated inputs (common in admission control).

### 3. Tune gRPC Server

```go
grpc.NumStreamWorkers(uint32(runtime.NumCPU() * 2))
grpc.MaxConcurrentStreams(1000)
```

**Impact:** Better connection handling under load.

---

## Benchmark Commands

```bash
# Install hey for HTTP benchmarking
go install github.com/rakyll/hey@latest

# Benchmark evaluation endpoint
hey -n 10000 -c 100 -m POST \
    -H "Content-Type: application/json" \
    -D input.json \
    http://localhost:8080/v1/evaluate

# Install ghz for gRPC benchmarking  
go install github.com/bojand/ghz/cmd/ghz@latest

# Benchmark gRPC
ghz --insecure \
    --proto api/proto/policy.proto \
    --call policy.PolicyService/Evaluate \
    -d '{"input": {...}}' \
    -n 10000 -c 100 \
    localhost:9090
```

---

## Summary

| State | Est. Throughput | Limiting Factor |
|-------|-----------------|-----------------|
| **Current (broken)** | ~100-200 req/sec | Shared CUE context |
| **Fixed (basic)** | ~1,000-2,000 req/sec | Sequential rule eval |
| **Optimized** | ~3,000-5,000 req/sec | CPU bound |
| **With caching** | ~10,000-15,000 req/sec | Network/memory |

**Recommendation:** Implement CUE context pool first—it's critical for correctness and provides the largest performance gain.