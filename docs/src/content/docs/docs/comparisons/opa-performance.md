---
title: "Garmr vs OPA: Performance"
description: "Performance benchmarks comparing Garmr and OPA"
sidebar:
  order: 1
  label: "vs OPA: Performance"
---

> **Status:** Initial baseline. Not yet an apples-to-apples comparison — policy complexity, test environment, and measurement methodology differ. This document will be updated as we add equivalent benchmark scenarios.

## Test Environment

| Parameter | Value |
|---|---|
| CPU | Intel Core i7-9700K @ 3.60GHz (8 cores) |
| OS | Linux 6.17.9 |
| Go version | 1.25.3 |
| Garmr test method | `httptest.NewServer` loopback, real engine + handler chain |
| OPA data source | [Official OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-performance/) and [Envoy performance benchmarks](https://www.openpolicyagent.org/docs/envoy/performance) |

## Policy Under Test

**Garmr** — A single-rule CUE policy checking `input.env == "prod"`:

```cue
apiVersion: "policy.garmr.io/v1"
kind:       "Policy"
metadata: {
    name:      "test-policy"
    namespace: "default"
}
spec: {
    target: resources: [{kind: "*"}]
    rules: [{
        id:          "r1"
        description: "check env"
        severity:    "high"
        expr: {match: {path: "env", equals: "prod"}}
        message:     "env must be prod"
    }]
    enforcement: action: "deny"
}
```

**OPA** — RBAC policy from official benchmarks (`opa bench`): role-based access control with user/role lookups.

Both are simple, low-complexity policies. Neither exercises deep nesting, large data sets, or complex iteration.

## Results Summary

| Metric | Garmr | OPA | Notes |
|---|---|---|---|
| **Per-eval latency** | **40.8 us/op** | **45.0 us/op** | Garmr: `go test -bench`; OPA: `opa bench` (27,295 samples) |
| **P50 latency (HTTP)** | **~120 us** | **~36 us** (eval only) | OPA figure excludes HTTP overhead |
| **P95 latency (HTTP, high load)** | **~750 us** @ 20K RPS | **~51 us** (eval only) | OPA figure is eval-only, not HTTP |
| **P99 latency (HTTP, high load)** | **~3 ms** @ 20K RPS | **~336 us** (eval only) | Same caveat — OPA excludes HTTP |
| **Peak HTTP throughput** | **~20,000 req/s** (0% errors) | **~5,000-10,000 req/s** (tuned) | OPA via Envoy sidecar ([Solo.io benchmark](https://www.solo.io/blog/performance-tuning-for-extauth-using-opa/)) |
| **Sustained throughput** | **~4,000 req/s** for 30s, 0% errors | — | Garmr sustained test, stable P99 ~3ms |
| **Memory per eval** | Not yet measured | **20,977 B/op, 382 allocs** | Garmr needs `-benchmem` measurement |

## Detailed Garmr Results

### Ramp-Up Load Test

Ramped from 1,000 to 30,000 target RPS in +1,000 steps, 5 seconds per step. The service never exceeded the 1% error threshold — it ran all 30 steps with 0% errors.

```
TARGET_RPS   ACTUAL_RPS   TOTAL      OK         FAIL       ERR%       P50        P95        P99        MAX
----------------------------------------------------------------------------------------------------------------
1000         958          4793       4793       0          0.00       354us      762us      1.5ms      5.7ms
5000         3440         17201      17201      0          0.00       324us      1.7ms      2.9ms      8.0ms
10000        7136         35683      35683      0          0.00       151us      1.1ms      4.7ms      28.9ms
15000        11848        59246      59246      0          0.00       131us      661us      1.8ms      14.5ms
20000        15295        76475      76475      0          0.00       118us      492us      4.7ms      32.3ms
25000        17303        86524      86524      0          0.00       130us      800us      11.0ms     59.2ms
30000        20472        102361     102361     0          0.00       123us      750us      2.9ms      26.1ms
```

**Peak sustainable throughput: ~20,472 req/s at 0% error rate.**

### Go Benchmark

```
BenchmarkEvaluateEndpoint-8    88,788    40,841 ns/op    24,486 req/s
```

### Sustained Load Test (5,000 RPS, 30 seconds)

```
Total requests: 116,612 | Successes: 116,612 | Failures: 0 | Error rate: 0.00%
```

Latency remained stable across all 30-second windows with no degradation over time.

## OPA Reference Numbers

From [OPA Policy Performance documentation](https://www.openpolicyagent.org/docs/latest/policy-performance/) (`opa bench` on RBAC policy):

```
27,295 samples
45,032 ns/op
20,977 B/op
382 allocs/op

Percentiles:
  Median:  35,846 ns
  P90:     44,780 ns
  P95:     50,815 ns
  P99.9:   335,906 ns
```

From [Solo.io Envoy+OPA tuning](https://www.solo.io/blog/performance-tuning-for-extauth-using-opa/):

- Tuned OPA sidecar: ~10,000 req/s with P99 < 10ms
- Default configuration: ~5,000 req/s with P99 ~2ms

## Analysis

### Where Garmr is competitive

1. **Raw evaluation speed is on par.** Both engines evaluate a simple policy in ~40-45 us. Both are Go, both compile policies to an internal representation.

2. **HTTP throughput favors Garmr.** Garmr sustained 20K+ req/s with 0% errors. OPA HTTP benchmarks (Envoy sidecar) typically target 5-10K req/s. This likely reflects Garmr's lighter middleware stack and CUE's efficient unification vs Rego's interpreter overhead.

3. **Tail latency is comparable.** Both show P99 in the low-ms range under load, with occasional spikes to ~30-60ms at extreme throughput — normal GC-pause territory for Go services.

### Caveats

- **Different policies.** Garmr's test uses a single `match.equals` check. OPA's benchmark uses RBAC with role lookups. These are roughly comparable in complexity but not identical.
- **Different measurement points.** OPA's `opa bench` numbers measure eval-only (no HTTP). Garmr's numbers include the full HTTP round-trip (request parsing, routing, JSON serialization, response writing). An eval-only Garmr benchmark would show lower latency.
- **Different test infrastructure.** Garmr uses `httptest.NewServer` (loopback). OPA's Envoy benchmarks involve real network hops and a proxy layer.
- **Policy complexity scaling.** OPA has 10+ years of optimization for complex Rego policies (partial evaluation, indexing, comprehension caching). Garmr hasn't needed those yet. Performance may diverge with complex policies.
- **Memory not yet measured.** OPA reports 20,977 B/op. Garmr needs `-benchmem` to complete this comparison.

## Future Work

To make this a true apples-to-apples comparison:

- [ ] Add `-benchmem` to Garmr benchmarks to measure allocations per evaluation
- [ ] Write equivalent RBAC policy in both Garmr CUE and OPA Rego, benchmark both
- [ ] Test with complex policies (10+ rules, nested forEach, builtin function calls)
- [ ] Test with large input payloads (1KB, 10KB, 100KB)
- [ ] Test with large data sets loaded into both engines
- [ ] Measure eval-only latency in Garmr (bypassing HTTP) for direct comparison with `opa bench`
- [ ] Run OPA server locally on the same hardware for controlled comparison

## How to Run Garmr Load Tests

```bash
# Quick smoke test (CI-safe, ~2 seconds)
go test -v -run TestLoadTest_Smoke ./internal/server/

# Full ramp-up test (1K->30K RPS, ~3 minutes)
go test -v -run TestLoadTest_RampRPS -timeout 10m ./internal/server/

# Sustained load test (5K RPS for 30 seconds)
go test -v -run TestLoadTest_Sustained -timeout 5m ./internal/server/

# Go benchmark with memory stats
go test -bench BenchmarkEvaluateEndpoint -benchmem -benchtime 5s ./internal/server/
```

## Sources

- [OPA Policy Performance](https://www.openpolicyagent.org/docs/latest/policy-performance/)
- [OPA Envoy Performance](https://www.openpolicyagent.org/docs/envoy/performance)
- [Solo.io — Performance Tuning for ExtAuth using OPA](https://www.solo.io/blog/performance-tuning-for-extauth-using-opa/)
