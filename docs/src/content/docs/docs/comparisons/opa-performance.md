---
title: "Garmr vs OPA: Performance"
description: "Like-for-like benchmarks of Garmr and OPA, in process and end to end over HTTP under load"
sidebar:
  order: 1
  label: "vs OPA: Performance"
---

Garmr and OPA were benchmarked at two levels on the same machine and the
same scenarios: the engines in process, and the real servers end to end over
HTTP under load ([End to end over HTTP](#end-to-end-over-http)).

## In-process engines

Both engines were called through their in-process Go APIs with each policy
compiled once up front:

- **Garmr:** `Engine.Evaluate` against a loaded policy set
  (`internal/engine/bench_test.go`).
- **OPA v1.21.1:** `rego.PreparedEvalQuery.Eval` with `rego.EvalInput`
  (`scripts/bench-opa/`, a separate Go module so OPA never becomes a Garmr
  dependency).

Both evaluate a Go `map[string]any` input, so both pay their own
input-conversion cost.

### Results

Intel Core i7-9700K @ 3.60GHz (8 cores), Linux, Go 1.25 (Garmr) / Go 1.26
(OPA module).

| Scenario | Garmr | OPA | Garmr speedup |
|---|---|---|---|
| **Simple** — 3 rules (equals, set membership, regex) on a Deployment | **3.0 µs**, 895 B, 6 allocs | 24.6 µs, 10.1 KB, 166 allocs | **~8×** |
| **Simple, parallel** (`b.RunParallel`, 8 cores) | **0.49 µs** | 5.7 µs | **~12×** |
| **500 policies**, input matches one (by kind) | **1.9 µs**, 7 allocs | 15.9 µs, 172 allocs | **~8×** |
| **forEach** over 50 elements, input padded with 200 objects | **16.5 µs**, 504 B, 7 allocs | 461 µs, 267 KB, 4,013 allocs | **~28×** |

Garmr's response is also the richer one: per-rule results, severity,
summary counts and evaluation mode, where the Rego query returns a set of
violation strings.

## End to end over HTTP

The in-process numbers leave out what a caller actually waits for: the
socket, HTTP, decoding the request and encoding the response. These runs
start the real `garmr-server` and `opa run --server` (OPA v1.21.1) binaries
and drive them with the same policies, the same request bodies and the same
load (`scripts/bench-e2e/`).

- **Verified first.** Before anything is timed, every scenario's allow and
  deny inputs are sent to both servers. The test checks that Garmr's
  `decision` and failed rule ids, and OPA's `deny` set, contain exactly the
  expected violations.
- **Isolated.** Each server is pinned to CPUs 0–3 with `GOMAXPROCS=4`. The
  load generator runs on CPUs 4–7. Traffic is HTTP/1.1 keep-alive on
  127.0.0.1, with the CPU governor set to `performance`.
- **Default logging off.** Garmr runs with `--audit=false`; OPA's decision
  logs are off by default. [Audit and decision logging](#audit-and-decision-logging)
  measures both with logging on.
- **Same request, different answers.** Garmr's `POST /v1/evaluate` returns
  per-rule results, severity and a summary: 395 B for an allow. OPA's
  `POST /v1/data/bench/deny` returns the violation set: 14 B for an allow.

**CPU/req** is the server process's user+system CPU time divided by the
requests it served, so it includes the kernel's loopback networking.

### One request at a time

One connection, 2,000 sequential requests.

| Scenario | Request | Garmr p50 / p99 | OPA p50 / p99 | OPA ÷ Garmr (p50) |
|---|--:|--:|--:|--:|
| Simple (3 rules) | 206 B | **90 / 224 µs** | 119 / 285 µs | 1.3× |
| 500 policies, input matches one by kind | 203 B | **86 / 201 µs** | 127 / 267 µs | 1.5× |
| 500 policies, all apply (1,500 rules), all pass | 206 B | **0.79 / 1.64 ms** | 2.04 / 5.04 ms | 2.6× |
| 500 policies, all apply, all 1,500 fail | 196 B | **2.54 / 4.55 ms** | 3.09 / 6.67 ms | 1.2× |
| `forEach` over 50 elements, 200 padding objects | 9.3 KB | **304 / 742 µs** | 650 µs / 1.55 ms | 2.1× |
| Simple, input padded to 10 KB | 9.4 KB | **309 / 725 µs** | 626 µs / 1.57 ms | 2.0× |
| Simple, input padded to 100 KB | 95 KB | **1.93 / 3.03 ms** | 5.24 / 6.80 ms | 2.7× |
| Simple, input padded to 1 MB | 991 KB | **20.5 / 25.6 ms** | 49.6 / 54.8 ms | 2.4× |
| Simple, input padded to 4 MB | 3.9 MB | **97.7 / 112 ms** | 217 / 244 ms | 2.2× |

In process, Garmr's lead on small policies was about 8×; end to end it is
1.3–1.5×. Of a 90–120 µs round trip, both servers spend roughly 85–95 µs
on HTTP and the network stack, and evaluating a small policy costs only a
few µs. The lead widens back to 2–2.7× wherever the engine's work dominates:
many applicable rules, iteration, and large inputs.

### Throughput and CPU cost

The closed-loop runs keep 1–256 connections busy back to back, using a 2 s
warmup and then a 10 s window, and report the median of 3 runs. Max req/s is
the best result across connection counts; input-size runs used 8
connections.

| Scenario | Garmr max req/s | OPA max req/s | Garmr ÷ OPA | Garmr CPU/req | OPA CPU/req |
|---|--:|--:|--:|--:|--:|
| Simple | **54.1k** | 36.0k | 1.5× | **66–70 µs** | 103–107 µs |
| 500 policies, matched by kind | **55.8k** | 34.5k | 1.6× | **67–71 µs** | 108–114 µs |
| 500 policies, all apply | **3.7k** | 1.0k | 3.6× | **1.07 ms** | 3.90 ms |
| `forEach` over 50 elements | **10.5k** | 4.1k | 2.6× | **365 µs** | 964 µs |
| Input 1 KB | **34.0k** | 19.1k | 1.8× | **99 µs** | 192 µs |
| Input 10 KB | **8.1k** | 3.6k | 2.2× | **417 µs** | 1.03 ms |
| Input 100 KB | **1.2k** | 474 | 2.6× | **3.1 ms** | 8.3 ms |
| Input 1 MB | **114** | 46 | 2.5× | **35 ms** | 86 ms |
| Input 4 MB | **23** | 11 | 2.1× | **172 ms** | 373 ms |

Both servers get within 5% of their maximum by 16 connections. More
connections only add queueing. At 256 connections on the simple policy:

| | Garmr | OPA |
|---|--:|--:|
| p50 | 2.74 ms | 1.21 ms |
| p99 | 24.7 ms | 108 ms |

OPA answers most requests faster here, but its slowest 1% wait four times as
long.

### Latency at equal offered load

The open-loop runs send at a fixed rate whether or not the server keeps up.
Latency is counted from each request's scheduled send time, so queueing
counts against the server. Up to 27k req/s, the generator sent within 20 µs
of schedule (p99). Above that, send delay grows with the server's backlog,
because all 256 of the generator's connections are busy.

| Offered req/s | Garmr p50 / p99 / p99.9 | OPA p50 / p99 / p99.9 |
|--:|--:|--:|
| 1k | 163 / 317 / 628 µs | 188 / 400 / 607 µs |
| 5k | 130 / 347 µs / 1.21 ms | 142 / 407 µs / 1.20 ms |
| 10k | 90 / 339 µs / 2.82 ms | 121 / 615 µs / 2.79 ms |
| 20k | **90 / 792 µs / 3.14 ms** | 119 µs / 3.66 / 8.25 ms |
| 27k | **94 µs / 1.56 / 4.04 ms** | 141 µs / 5.40 / 21.5 ms |
| 40k | 114 µs / 7.16 / 22.5 ms | saturated: 33.1k served, queue grows |
| 80k | saturated: 47.8k served | saturated: 26.1k served |

- **Light load (up to 5k req/s):** the two are within 10–30% of each other.
  The p99.9 is the same on both.
- **Medium load:** the gap opens because OPA uses about 50% more CPU per
  request, so it gets close to its limit sooner. At 20k req/s, Garmr's p99 is
  4.6× lower.
- **Highest sustained rate:**

  | | Garmr | OPA |
  |---|--:|--:|
  | Rate held | 48.7k req/s | 32.4k req/s |
  | p99 at that rate | 12.9 ms | 40.8 ms |

### Audit and decision logging

The same open-loop rates were run with logging on:
- Garmr: `--audit`, writing to a file.
- OPA: `decision_logs.console=true`.

| Offered req/s | Garmr p99, off → on | Garmr CPU/req, off → on | OPA p99, off → on | OPA CPU/req, off → on |
|--:|--:|--:|--:|--:|
| 5k | 347 → 361 µs | 115 → 108 µs | 407 → 958 µs | 149 → 215 µs |
| 20k | 792 µs → 3.80 ms | 74 → 95 µs | 3.66 → 432 ms (saturated, 19.2k served) | 109 → 197 µs |

Garmr's audit log adds 0–20 µs of CPU per request. OPA's console decision
logger almost doubles OPA's CPU per request, and OPA can no longer sustain
20k req/s with it on.

This compares Garmr's production audit path with OPA's simplest logger.
Production OPA usually ships decision logs through the buffered remote
decision-log plugin, which was not measured.

### Startup and memory

The time is from exec to the first `200` from Garmr's `/ready` or OPA's
`/health`, median of 3. RSS was read right after ready. Each policy has 3
rules.

| Policies | Garmr ready | OPA ready | Garmr RSS | OPA RSS |
|--:|--:|--:|--:|--:|
| 1 | **14 ms** | 20 ms | **27 MB** | 38 MB |
| 10 | 25 ms | **20 ms** | **29 MB** | 39 MB |
| 100 | 136 ms | **40 ms** | **36 MB** | 44 MB |
| 500 | 684 ms | **201 ms** | 63 MB | **61 MB** |
| 2,000 | 3.86 s | **2.25 s** | 171 MB | **121 MB** |
| 5,000 | 17.2 s | **15.3 s** | 386 MB | **231 MB** |

Load time grows faster than the policy count on both servers. Garmr is
slower from 10 policies up, most of all between 100 and 500 policies
(3.4×). The gap narrows to 1.1× at 5,000 policies.

Memory:
- Garmr starts smaller.
- It holds about 75 KB per policy, against about 40 KB for OPA.
- It passes OPA at around 500 policies.

During a 2-minute soak at 18k req/s, both servers stayed flat:

| | Garmr | OPA |
|---|--:|--:|
| RSS | 33–35 MB | 50–53 MB |
| p99 in each 20 s window | 0.9–1.8 ms | 1.9–3.2 ms |

### Reloading policies under load

This test sent 9k req/s against 500 indexed policies. It rewrote the policy
that the input matches and applied the change while the load ran:
- Garmr: `POST /v1/policies/reload`.
- OPA: `PUT /v1/policies/{id}`.

| | Reload call | p99 before | p99 during | Slowest request during | Errors |
|---|--:|--:|--:|--:|--:|
| Garmr | 789 ms | 363 µs | **638 µs** | **5.3 ms** | 0 |
| OPA | **416 ms** | 2.31 ms | 187 ms | 229 ms | 0 |

Both servers served the new policy as soon as the call returned, with no
stale answers afterwards.

Garmr takes almost twice as long to reload, but traffic doesn't notice. It
builds the new policy set separately, then swaps it in atomically.

OPA's reload is faster, but requests that arrive while it reloads wait for
it, up to 229 ms. Only the policy API was measured, not bundle activation.

## Where each one is stronger

**Garmr:**
- **Throughput and cost.** It serves about 1.5× the requests per second and
  uses about 35% less CPU per request on ordinary policies.
- **Heavy evaluations.** It is 2–3.6× faster when many rules apply, on
  `forEach`, and on large inputs.
- **Tail latency under load.** It keeps a sub-millisecond p99 up to 20k
  req/s, where OPA's p99 is already 3.7 ms. It sustains about 50% more load
  before saturating.
- **Reloads that traffic doesn't notice**, and a cheap audit log.
- **Smaller memory footprint** below about 500 policies.

**OPA, and where Garmr's edges are:**
- **Startup and reload time.** Garmr compiles CUE when policies load. At
  100–500 policies it is 3.4× slower to start, and at 500 policies it is
  1.9× slower to reload. It is slower to start from 10 policies up. This matters for cold starts, autoscaling and frequent
  reloads.
- **Memory per policy.** Above about 500 policies, Garmr uses more RSS: 1.7×
  OPA's at 5,000 policies.
- **Response size.** Garmr's response is richer, and it costs time when
  many rules fail.
  - With 1,500 failing rules, Garmr returns 365 KB against OPA's 14 KB.
  - Garmr's latency triples, from 0.79 ms to 2.54 ms.
  - Its lead shrinks to 1.2×.
- **Bytes of input.** Garmr spends about 20 ns per input byte. Request
  decoding uses `encoding/json` into maps, and that dominates above about
  10 KB: a 1 MB input takes 20 ms. Garmr is still 2.4× faster than OPA here,
  but this is where its absolute cost grows.
- **HTTP is now most of the cost.** For a small policy, evaluation is about
  3 µs of roughly 70 µs of CPU per request. Further engine speedups will
  barely show end to end. The remaining gains are in the HTTP and JSON layer.

## Why Garmr is fast

- **CUE only at load time.** Each policy is unified with the schema,
  hashed, and every rule's expression is compiled into a Go evaluation tree:
  paths are pre-split, regular expressions, semver and datetime literals are
  parsed, and `in`/`subsetOf` lists become hash sets. Evaluation walks the
  request's decoded JSON directly.
- **No shared mutable state on the hot path.** The policy set is an
  immutable snapshot behind an atomic pointer; evaluations read it without
  locks and run fully in parallel. Reloads build a new set and swap it.
- **Kind index.** Policies whose targets name concrete kinds are indexed, so
  finding applicable policies does not scan the whole set.
- **`forEach` binds by reference.** An element is bound to the alias in a
  scope frame, with no copy of the input per element.

The largest remaining per-request cost on big inputs is a single walk that
confirms the input is JSON-shaped (and converts it once if a Go caller passed
typed values). It is O(input), like JSON decoding, which costs more.

## Before this engine

Garmr previously evaluated by walking CUE values per request and encoding
the whole input into CUE, with at most 8 evaluations in parallel (one per
CUE context replica). On the same benchmarks: simple policy 226 µs / 3,447
allocs, 500 policies 531 µs, and the forEach scenario **58 ms**.

## Caveats

- The in-process numbers leave out HTTP and JSON. The end-to-end numbers
  include them, but use 127.0.0.1 on one machine. A deployment adds a
  network or sidecar hop on both sides. That hop makes the small-policy
  gap narrower still, and leaves the server CPU per request unchanged.
- The end-to-end OPA query returns a violation set, which is idiomatic
  Rego. A Rego policy that returned per-rule results like Garmr's would cost
  OPA more; that was not measured.
- OPA can pre-convert input (`rego.EvalParsedInput`) to skip its input
  conversion; that would narrow the large-input gap but not the others.
- Rego is more expressive (variables, joins, comprehensions, user
  functions). Garmr's speed comes partly from a deliberately smaller,
  declarative operator set.

## Reproducing

```bash
# Garmr
go test ./internal/engine -run '^$' -bench 'BenchmarkEvaluate|BenchmarkForEach' -benchmem

# OPA (separate module; downloads OPA)
cd scripts/bench-opa && go test -run '^$' -bench . -benchmem

# Garmr over HTTP (httptest, no OPA)
go test ./internal/server -run '^$' -bench BenchmarkEvaluateEndpoint -benchmem

# End to end, both real servers (~40 min; builds garmr-server and OPA v1.21.1).
# Set the performance governor first for stable numbers. Results land in
# scripts/bench-e2e/results/<timestamp>/{results.json,summary.md}.
make bench-e2e                 # or: scripts/bench-e2e/run.sh -phases verify,closed
make bench-e2e ARGS=-quick     # ~5 min smoke run

# Load tests (ramp, sustained)
go test -v -run TestLoadTest_RampRPS -timeout 10m ./internal/server/
go test -v -run TestLoadTest_Sustained -timeout 5m ./internal/server/
```
