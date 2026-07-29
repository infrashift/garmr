# TODO — Recommended Feature Work

Feature gaps identified during the 2026-07 code/docs reviews. These were
deliberately **not** implemented (the review branches fixed bugs, removed
debt, and aligned docs); they are recorded here so the ideas aren't lost.

Three rounds are recorded: `feature/refactor` (2026-07-08/09),
`feature/review-fix-refactor` (2026-07-28), and the pre-production
hardening pass (2026-07-28, Phases A–G) targeting the Nomad + Consul
Connect deployment.

## Engine — deferred cleanups (behavior-neutral)

1. Replica rebuild cost: `LoadPolicy` recompiles the source once per replica
   (K× compiles). Fine for startup/tests; if bulk incremental loading ever
   becomes a hot path, add a batch-load API.
2. `forEach` per-element cost is still O(input size) inside CUE itself: each
   element context is a new value tree that CUE re-evaluates on lookup
   (measured ~1.4 ms/element on a 200-field input vs ~60 µs on a small one;
   see `BenchmarkForEach_LargeInput`). Our plumbing is already minimal
   (FillPath, no decode/re-encode). Fixing this means layered path
   resolution (element struct first, falling back to the original input
   value) threaded through every operator's lookup — only worth it with
   profiling evidence from real large-document workloads.

## Implemented since the review

- **Advanced set operators** (2026-07-08): `unique`, `uniqueBy`, `sorted`,
  `containsAll`, `subsetOf` as `match:` operators
  (`internal/engine/expr_set.go`), documented in
  `reference/policy-schema.md`, demonstrated by the `set-advanced` example
  policy and `testdata/condition-operators/` fixtures.
- **`garmr test` rebuilt on the real engine** (2026-07-09): the runner
  (`internal/testing/runner.go`) now loads policy files through
  `engine.LoadPoliciesFromFile` and asserts against real `Evaluate`
  responses, keyed by policy `metadata.name` (or `"namespace/name"`).
  Violations map to failed rules; target mismatches surface as `no-match`
  violations. Worked example: `example-policies/real-world/release-gate_test.cue`.
  `garmr validate`/`policy lock` skip `*_test.cue` files, and the server's
  policy-directory loader ignores them (they carry no package clause).
- **Semver parser consolidation** (2026-07-09): the `semver` builtin now
  uses the strict parser and comparator from `expr_semver.go`. Behavior
  change: prerelease precedence is now spec-correct (`1.0.0-rc.1` sorts
  before `1.0.0`; the old duplicate parser treated them as equal).
- **`forEach` element contexts via FillPath** (2026-07-09):
  `createItemContext` grafts each element onto the existing input value
  instead of decoding and re-encoding the whole input per element (~1.2×
  faster on large inputs, far less allocation). A rebuild fallback preserves
  replace semantics when the alias or `_index` collides with an input field
  or a nested `forEach` re-binds them. The remaining per-element cost is
  CUE-internal — see deferred cleanup #2.

## Implemented in the pre-production hardening pass (2026-07-28, Phases A–G)

- **Multi-operator AND semantics** (Phase A): condition blocks silently
  enforced only the first operator in dispatch order — fail-open.
  `match`/`length`/`semver`/`datetime` now evaluate every specified
  operator and AND the results (`evaluateAllSpecified` in
  `internal/engine/helpers.go`); violations name each unmet check.
- **One schema, enforced on the production path** (Phase B): resolves old
  item #3. `schemas/policy.cue` is embedded via go:embed (the `schemas` Go
  package) and unified with every document the directory loader compiles.
  The diverged hand-maintained copy in `engine.go` is gone. `#Rule.id` was
  relaxed to a bounded token; `#Rule.expr` stays `_` because raw CUE
  constraint expressions are a feature.
- **Fail-closed loading + serialized mutations + digest** (Phase C):
  resolves old item #4. Compile/schema failures abort the load naming the
  policy; zero policies fails startup (nonzero exit) and reload (HTTP 500,
  old set retained); `Engine.loadMu` serializes reload build+swap against
  all mutations. Every policy carries a canonical-content sha256 and the
  set digest is served by `GET /v1/policies` and reload, reproducible
  offline with `garmr policy digest`.
- **Readiness reflects shutdown; TLS deleted** (Phase D): `/readyz` is 503
  before Start and from the instant Stop() begins draining. The TLS
  listener, flags, config keys, and the rate limiter's unreachable "cert"
  identifier were removed — the mesh owns transport security.
- **Local-first `garmr validate` + `garmr policy digest`** (Phase E):
  validate runs the server's exact loader locally (multi-file CUE packages
  now validate; no in-mesh CI runner needed); `--remote` keeps the server
  path. Dead `--warn`/`--strict` and phantom line/column rendering removed.
  The lock-file "on-demand reload" fiction was excised from CLI help and
  docs.
- **Nomad deploy assets; container/build fixes** (Phase F):
  `deploy/nomad/` service + parameterized batch jobs + pipeline README;
  HEALTHCHECK scheme fixed; docker Make targets point at Containerfile;
  CI builds and smoke-tests the image.

## Deferred from the pre-production hardening pass (2026-07-28)

Recorded, deliberately not done before the deploy:

- ~~**Dead code**~~ — done (2026-07-28, follow-up commit). Deleted: the
  `health` placeholder checkers (`PluginChecker`, the unconditionally-healthy
  `DiskSpaceChecker`/`MemoryChecker`, plus the superseded
  `PolicyLoaderChecker`/`StorageBackendChecker`), `health.SetLive`/
  `Unregister` (liveness is deliberately constant — a test now pins the
  always-200 contract), `ratelimit.AllowN`/`Wait`/`ClientCount` (the two
  tests that used `ClientCount` to assert the map bound now read the map
  directly in-package), `input.ParseBytes`/`ToJSON*`/`ToYAML`/`Supported*`,
  `engine.ClearPolicies` (and `forEachExclusive` folded away — `DeletePolicy`
  now goes through `mutateAll` with an infallible prepare),
  `PrometheusMetrics.Registry`, and the `internal/testing` dead fields
  (`TestExpectation.Output`, `ActualResult.Output`, `TestCase.Context`
  including its parse-then-ignore block). `engine.LoadPolicy` was kept as
  the engine's in-memory load API — the test suites in three packages build
  fixtures with it, and its doc comment now states it has no production
  caller.
- ~~**Duplication**~~ — done (2026-07-28, follow-up commit). The six
  identical CLI client-construction blocks collapsed into
  `newServerClient()` in `cmd/garmr/commands.go` (`runHealth` keeps its own
  construction deliberately: it has a `--wait` retry loop and different
  timeouts). `Load*/Reload* FromBackend` now share `withBackendDir`.
  `getNestedString` (server) deleted in favor of the exported
  `engine.NestedString`. The three ~35-line sort comparators reduced to two
  compare primitives plus a comparator chain in `sortRules`, with
  `TestSortRules_Orders` pinning the ordering contract for all four
  evaluation orders (written against the old implementation first, then the
  refactor verified against it).
- ~~**Oversized functions**~~ — done (2026-07-28, follow-up commit).
  `Evaluate` 219→110 lines (outcome merging extracted into an
  `evalAccumulator` with engineFailure/fold/noteFailFast/finish phases,
  plus `minPolicyTimeout`); `evaluateExpression` 124→42 (a pure dispatcher
  over extracted `evaluateAll`/`evaluateAny`/`evaluateNot`/
  `evaluatePathPresence`/`evaluateRawConstraint`); `handleEvaluate` 113→46
  (pure `parseEvaluateRequest` + `auditDecision`); `runTest` 143→45
  (`collectTestFiles`/`runTestSuites`/`filterTestCases`). runTest was at
  ~4% coverage, so nine tests were written against the old implementation
  first — and immediately caught a real bug: `garmr test <dir>` without
  --recursive SkipDir'd the walk root and always reported "no test files
  found"; fixed in the split. Everything else was refactored under the
  existing engine/server nets plus a -race pass.
- ~~**Error-shape inconsistency**~~ — done (2026-07-28, follow-up commit).
  Every error response now carries the same {"error": ...} JSON shape: the
  six plain-text `http.Error` sites (four 405s, missing-input 400,
  no-policy-source 400) go through `writeError`, the rate limiter's 429
  emits JSON, and an over-limit body is now correctly 413 (was a generic
  400) on both /v1/evaluate and /v1/validate.
  `TestErrorResponses_AllJSON` pins the contract across eleven error
  paths. Writing that test exposed a real bug: RetryIn was computed as
  `time.Second / time.Duration(rps)`, which truncates any fractional rate
  to zero and panics with divide-by-zero — every rejected request under a
  sub-1-rps limiter became a 500 instead of a 429. Fixed (`retryIn()` in
  the limiter) and pinned. rest-api.md's status table now lists
  401/405/413/429 and the honest one-field error shape; openapi.json's
  reload 400 is JSON.
- ~~**Client query-param escaping**~~ — done (2026-07-28, follow-up
  commit). `DeletePolicy`/`ListPolicies` build their query strings with
  `url.Values.Encode()` (the raw-Sprintf locals also shadowed the `url`
  package); `TestClient_QueryParamsEscaped` pins that names/namespaces
  containing `&`/`#`/`=`/spaces arrive server-side as data.
- ~~**Rate limiting behind a sidecar**~~ — done (2026-07-28, follow-up
  commit). New `client_identifier: identity` mode keys per-client buckets
  on the mesh-verified SPIFFE URI from the XFCC header (falling back to
  the client IP — fails safe as a shared bucket — when the header is
  absent); the XFCC parsing moved to the shared `internal/xfcc` package so
  the limiter and the server's audit principal use one implementation.
  Every per-client knob is now configurable (`rate_limit.per_client`,
  `client_identifier`, `header_name`, `client_rps`, `client_burst`,
  `max_clients`) with flags, viper keys, and docs.
  `TestRateLimit_KeyedByMeshIdentity` drives the full middleware chain:
  two identities from the same source address get independent buckets.
  The "identity" mode must only be enabled when a sidecar owns the XFCC
  header — documented in config.example.yaml, configuration.md, and the
  Nomad README.
- ~~**`/health/deep` quirks**~~ — done (2026-07-28, follow-up commit).
  Kept: it is the only endpoint that verifies the policy volume is still
  mounted and readable after startup (the storage round trip). The status
  code is now honest — 200 only when every check is healthy, 503 otherwise,
  per-check detail in the body — pinned by tests including a live
  volume-goes-away case. The API-key requirement is kept deliberately and
  now documented + pinned: probes can't carry credentials so
  /healthz//readyz//livez stay exempt, while /health/deep performs storage
  I/O on every call and stays gated. openapi.json, rest-api.md, and
  deploying.md all state both behaviors.
- ~~**Hardcoded server limits**~~ — done (2026-07-28, follow-up commit).
  `max_recv_size`, `read_timeout`, `write_timeout`, `idle_timeout` are now
  flags + viper keys + Config fields, with the old hardcoded values as
  defaults (an empty Config changes nothing — pinned by test). The
  configuration reference gained an "HTTP Limits & Timeouts" section that
  states the memory pairing (evaluate buffers the whole body: 16 MiB ×
  concurrency vs the container limit) and the Envoy reconciliation rule
  (keep write_timeout ≥ the proxy's request timeout, idle_timeout above
  the proxy's idle timeout).
- ~~**Metrics gaps**~~ — done (2026-07-28, follow-up commit).
  `garmr_policy_reloads_total{result}` counts reload outcomes (recorded in
  `ReloadPoliciesFromDir`, covering the endpoint and backend paths — alert
  on failures, which keep the old set serving). The staleness fix changed
  the recorder contract: `SetPoliciesLoaded` now takes a full per-namespace
  snapshot (Reset + set in the Prometheus impl), published by each mutation
  (load/reload/delete) from the resulting set, so a vanished namespace
  drops out of the series instead of exporting its last value forever —
  which also fixed per-batch counts overwriting each other. Pinned at the
  recorder level and end-to-end (reload dirA → dirB, team-a disappears
  from the exposition; failed reload increments the failure counter and
  leaves the gauge untouched).
- ~~**Swagger UI loads swagger-ui-dist from unpkg.com**~~ — done
  (2026-07-28, follow-up commit): dropped rather than vendored. The page
  silently broke in the egress-restricted target deployment, nobody
  browses a sidecar-fronted machine-caller service, and vendoring ~1.3MB
  of minified JS for a debug page wasn't worth the supply-chain surface.
  /openapi.json remains the supported surface; rest-api.md shows how to
  point a local viewer at it, and a test pins that /swagger-ui now 404s.
- ~~**Docs accuracy sweep (remainder)**~~ — done (2026-07-28, follow-up
  commit). policy-loading.md's fictional namespace-resolution modes
  replaced with the truth (metadata.namespace only; directories are a
  convention) and its `garmr serve` + CUE-config container example
  replaced with the real Containerfile/garmr-server/YAML story; README
  gained the set operators, the AND-semantics note, and honest reload
  phrasing (explicit, fail-closed — not "hot"); `GARMR_CONFIG` was made
  real instead of deleting the doc row (the CLI now reads it when
  --config is absent); `./.garmr.yaml` name corrected; `garmr test` flag
  table says `--format`; storage-backends now states what the
  include/exclude patterns actually govern (the List operation feeding
  /health/deep, not policy loading). `docs/demo/NLIT-2026.md` was audited
  rather than deleted: every command uses current flags and every
  referenced fixture exists — it stays as deliberate off-site demo
  material.
- ~~**Per-alloc reload fan-out**~~ — done (2026-07-28, follow-up commit).
  `garmr policy reload --servers a,b,c --expect-digest <hex>` fans out to
  every instance, verifies each against the checkout's digest, and exits
  nonzero on any failure, digest mismatch, or divergence between
  instances (single-instance behavior and JSON shape unchanged). Fixed
  along the way: a failed reload used to print ✗ and exit 0 — it exits 1
  now, pinned by test. The Nomad README's shell loop is replaced with the
  one-command fan-out (addresses from `nomad service info`).
  `DELETE /v1/policies` divergence is addressed with honesty rather than
  fan-out: its help text now states it mutates one instance's memory,
  comes back on the next reload/restart, and that removing a policy for
  real means deleting it from git and deploying.
- ~~**Audit log shipping**~~ — done (2026-07-28, follow-up commit) by
  handing shipping to the platform instead of building a shipper:
  `audit.path` accepts the literal `stdout`/`stderr`, streaming records
  to the process streams that Nomad/K8s log capture already ships
  off-node (application logs go to stderr, so audit-to-stdout keeps the
  streams separable; rotation settings don't apply — the platform owns
  retention; Stop() never closes the process streams). The Nomad service
  job now runs `--audit-path stdout`, and the docs recommend it for mesh
  deployments while keeping file mode for file-tailing setups. Pinned
  end-to-end: an evaluation with an XFCC header lands a JSON decision
  record carrying the SPIFFE principal on stdout.

## Resolved by removal (2026-07-28)

- **S3 / MinIO storage backend** — decided against. 494 lines at 7.3%
  coverage with zero unit tests; its only real tests were behind
  `//go:build integration` and needed podman plus a MinIO pod, and CI never
  passed `-tags integration`, so it was compiled and never exercised on any
  PR. It cost `minio-go` plus 10 indirect modules to deliver a path that
  staged every object into `os.MkdirTemp` and loaded it from disk anyway —
  an in-process reimplementation of `aws s3 sync` with worse credential
  handling, and the Helm block would have written cloud credentials into a
  plaintext ConfigMap. The supported story is now to sync objects onto the
  pod (init container running `mc mirror` / `aws s3 sync`, or a CSI volume)
  and point `--policy-dir` at the mount, which keeps credentials in a Secret
  or IRSA. The `storage.Backend` interface, registry and `stageBackendFiles`
  were kept: they give `initStorageBackend` fail-fast validation, give
  `/health/deep` a real signal, and make re-adding a backend a one-file
  change. If revived, it needs unit tests, MinIO as a CI service container,
  and `existingSecret`/IRSA support in the chart.
- **`Backend.Watch` / `Event` / the fsnotify filesystem watcher**
  (2026-07-28) — decided against. Zero production callers; the only ones
  were their own tests, so `--s3-poll-interval` controlled nothing. Wiring
  the existing watcher up would not have helped the deployment that matters:
  Kubernetes projects a ConfigMap by swapping a `..data` symlink,
  `filepath.WalkDir` does not follow symlinks, and the resulting events
  never match `**/*.cue` — it would have appeared to work in `make dev` and
  silently done nothing in production. Reload stays explicit
  (`POST /v1/policies/reload`), plus the chart's `checksum/config`
  annotation which rolls pods when the ConfigMap changes. If revived, real
  hot reload needs a debounced poller over `List` + `Checksum` that resolves
  symlinks (not inotify path matching), an atomic swap, a `reload.interval`
  knob, and a `garmr_policy_reloads_total` metric so operators can see it
  working.
- **`internal/validation`** (2026-07-28) — decided against. 429 lines at 0%
  coverage imported by nothing, defining a second `ValidationError` that
  competed with the real one in `engine/types.go` (the `/v1/validate` wire
  format). Input validation is the policy's job: express it in `expr` and
  let CUE do it. If revived, design it as a per-policy input schema
  (`spec.inputSchema`) unified with the request input before evaluation,
  surfacing failures as a distinct `invalid-input` verdict rather than a
  violation.
- **`internal/builtin`** (2026-07-28) — decided against. 328 lines at 0%
  coverage imported by nothing, left over from the plugin retirement in
  cc74a23 and still describing itself as "built-in plugins". Its
  `DefaultLogger` and `DefaultAuditLogger` were superseded by the server's
  zap logger and the `slog` + lumberjack audit writer.
- **Dead CUE schemas** (2026-07-28) — `schemas/plugins.cue`,
  `schemas/config.cue`, `schemas/observability.cue` and
  `schemas/storage.cue` deleted (1,413 lines). No Go code has ever read
  `schemas/`; the only `//go:embed` is `openapi.json`. All four described
  things that do not exist: an Ed25519-signed `.so` plugin loader with a
  trust store (retired in cc74a23, and internally invalid —
  `verifyChecksums` was not a field of the struct that set it), a gRPC
  server (retired in 001cd21), watch/poll/ondemand/jit reload strategies, an
  engine result cache, a Kafka audit sink, and `gcs`/`azure` backends. All
  four also still carried the pre-rename `apiVersion: "config.q.io/v1"`.
  Deleting them is what finally made `make cue-vet` run: `schemas/` held two
  CUE packages, which CUE refuses, so the whole tree had been unvalidated
  indefinitely.
- **CUE policy sets** (2026-07-28) — decided against. `schemas/policyset.cue`
  (251 lines) described a `kind: "PolicySet"` manifest with `include`
  ordering, unified `definitions`, `evaluationOrder: "dependency"` and
  per-policy `requires`. None of it was implemented — no Go code loads a
  manifest — and `requires` had already been decided against on 2026-07-09.
  The file had also never parsed: it used `/* */` comments, which CUE does
  not have, so nothing had ever vetted it, and it defined `#PolicySet` a
  second time in conflict with a stub in `policy.cue`. Multi-file policies
  are served by CUE packages, which already work and are now what
  `policy-loading.md` documents. If revived, it needs a real loader, and the
  dependency ordering brings back everything `requires` was rejected for.
- **Observability plugin surface** (2026-07-28) — decided against. The
  `Tracer` interface, `NoopTracer`, `AuditLogger`/`AuditEntry`/
  `AuditViolation` and `Provider`'s tracer/audit accessors had zero callers
  outside the package: tracing is real but arrives via `otelhttp` +
  `InitTracing` + `TraceIDFromContext`, and audit is a raw `slog.Logger` in
  the server. Four `MetricsRecorder` methods (`RecordCacheHit`,
  `RecordCacheMiss`, `RecordInputValidationError`, `SetPluginHealth`) and
  their Prometheus collectors went with them — an empty `CounterVec` emits
  no samples, so those series never appeared in `/metrics` and nothing could
  have depended on them. `RecordRateLimitHit` was kept and is now actually
  incremented.
- **Evaluation trace (`--trace`)** (2026-07-28) — decided against. It was
  plumbed end to end (CLI flag → `client.EvaluateOptions` → server request
  field → `EvaluateOptions.Trace` → `resp.Trace`) and documented in
  `openapi.json`, but nothing ever appended a `TraceEvent`: the flag
  returned an empty array. Removed rather than left as a documented no-op.
  What the response *does* now carry is `summary`, `evaluation_mode`,
  `terminated_early` and `termination_rule`, which the engine had always
  computed and the API had always dropped. If a real trace is revived, it
  needs per-rule events emitted from `evaluateRule` (operator, resolved
  operands, outcome, duration), a size cap so a `forEach` over a large
  document cannot blow up the response, and a decision about whether traces
  are safe to return to an untrusted caller — they echo input values.
- **Silently-ignored policy schema fields** (2026-07-28) —
  `spec.target.conditions`, `spec.enforcement.webhook` and
  `spec.rules[].continueOnFail` were declared in the embedded schema and
  never consulted. The first two were fail-open: a policy narrowed by
  `conditions` matched everything, and `webhook` implied a callout that
  never happened. All three are now rejected at compile time with an
  actionable error, following the `expr.ref` precedent — `continueOnFail`
  points authors at `spec.evaluation.failFast`, which is the real mechanism.
  `#Rule.url`, `#Exception.approvedBy` and `#Exception.ticket` were kept:
  they are author metadata rather than engine mechanisms, and the shipped
  examples use them. Also removed: `TraceEvent`,
  `EvaluateOptions.Instrument`, `Metrics.CompileTimeNs`/`CacheHit`, the
  `Priority*` category constants (the `Priority` field and priority sorting
  are live), and the unused `ErrEvaluationFailed`/`ErrCompilationFailed`.
- **`compare` operands from the server environment** (2026-07-28) — decided
  against. `{env: "NAME"}` resolved to `os.Getenv`, and violation messages
  interpolate resolved values back to the caller, so any policy author could
  exfiltrate credentials over `/v1/evaluate`. Policy authors are not
  necessarily server operators. Removed from `resolveValue` and from
  `schemas/policy.cue` along with the never-implemented `{data: ...}`, and
  both now fail with an explanation rather than resolving to nil. Inject the
  value into the evaluation input instead, where it is auditable.
- **Dead CLI flags** (2026-07-28) — `policy list --label`,
  `policy reload --force` and `docs generate --author` were declared and
  never read; `eval --trace` always returned nothing. All removed.
  `policy delete --force` is read and stays.
- **Generated policy documentation pages** (2026-07-28) — decided against
  tracking them. The 18 files under
  `docs/src/content/docs/docs/policies/generated/` were wired into the Astro
  sidebar via `autogenerate`, but nothing regenerated or verified them:
  most described policies that no longer existed, while whole example
  families had no page at all. `garmr docs generate` still works, is
  offline, and is now demonstrated as a feature users point at their own
  policies. A hand-maintained catalog page replaced the tree. If revived as
  site content, the generator needs stable output ordering and
  `sidebar.order`, plus a `make docs-policies` target and a
  `git diff --exit-code` drift check in CI — otherwise it rots again.

## Build and CI hygiene (fixed 2026-07-28)

- `make cue-vet` and `make lint` now run. They had been failing indefinitely:
  `schemas/` held two CUE packages, and `policyset.cue` did not parse. Both
  `cue vet` and `cue fmt --check` are now enforced in CI over `schemas/` and
  `example-policies/`.
- `gofmt` is enforced in CI. Three tracked files had drifted because nothing
  checked.
- `golangci-lint` is pinned (was `version: latest`, so an upstream release
  could break CI with no change here) and `.golangci.yml` pins the linter
  set.
- The Astro docs site is built on every PR. `docs-release.yml` only triggered
  on push to `main`, so a broken docs build was found after merge.
- `make test` gained `-short`; the load tests moved to `make test-load`, so
  `make release` no longer runs 5000 RPS for 30s under `-race`.
- Deleted the phantom `make test-integration` target
  (`scripts/integration-test.sh` never existed) and the stale
  `grep -v '/plugins/'` package filters.
- Deleted `docs/pnpm-lock.yaml`; it and `bun.lock` were both tracked, so CI
  and local dev could resolve different dependency trees.
- Added `internal/engine/examples_test.go`: no Go file referenced
  `example-policies/`, so the product's showcase was compiled by nothing.

## Resolved by removal (2026-07-08)

- **Data storage API** — decided against. The dormant engine subsystem
  (`internal/engine/data.go`: `SetData` never consulted during evaluation,
  `DeleteData` a no-op) and the `#DataSource`/`#AuthConfig` schema
  definitions were deleted along with the CLI stubs. If external data is
  ever needed, design it fresh (data wired into evaluation input + `/v1/data`
  endpoints) rather than reviving the old surface.
- **`garmr policy push`** — decided against for now. The CLI stub was
  removed and no upload endpoint exists; policies are managed through the
  policy directory / storage backend and hot reload. If revived, it needs a
  server upload endpoint with schema validation and audit logging.
- **CLI authentication + TLS** — decided against for now. The CLI is
  intended for trusted networks or behind a mesh sidecar (the server's
  `auth.identity_header` deployment model); the server's API-key auth
  remains for non-CLI REST callers. The never-consumed `--insecure`/
  `--tls-cert` flags stay removed. If revived: add `--api-key`
  (or `GARMR_API_KEY`), `--tls-cert`, `--insecure`, thread through
  `client.Config`, send the key in the configured header.
- **Multi-namespace evaluation** — decided against for now. `-n` is
  single-valued end-to-end; the unused `EvaluateRequest.Namespaces` field
  was removed. Run one `garmr eval` per namespace instead. If revived, wire
  a repeatable `-n` through client, server request parsing, and the engine.
- **`garmr docs generate` output formats** — decided against for now. Only
  `generic-markdown` exists; the "future formats" advertising was removed
  from the command help.
- **Table-driving `evaluateMatch`** (2026-07-09) — decided against. The
  motivating scenario ("duplication costs you when adding operators") was
  tested by adding the five set operators: the natural shape turned out to
  be delegation to per-family files (`expr_set.go`, `expr_semver.go`,
  `expr_datetime.go`), not a dispatch table. The remaining inline branches
  are simple, uniform, and exhaustively tested, and their handler shapes are
  heterogeneous (bool vs regex vs float vs list decode), so a table would
  add indirection without removing complexity — negative expected value on
  the engine's hottest correctness surface.
- **mTLS** (2026-07-09) — decided against: mutual TLS is handled by the
  Consul service mesh (the sidecar terminates client mTLS and forwards the
  verified SPIFFE identity via `auth.identity_header`; see
  `deploy/helm/garmr/examples/consul-connect/`). Update 2026-07-28: the
  plain server-side TLS listener was removed as well (Phase D) — the
  server is HTTP-only, and non-mesh deployments front it with a
  TLS-terminating proxy.
- **`expr.ref` and `spec.requires`** (2026-07-09) — decided against
  together; both were never implemented. `ref` and `requires` were removed
  from the schemas; `ref` is additionally rejected at policy compile time
  (with an evaluation-time fail-closed backstop for refs nested inside
  all/any/not, which the compile check cannot see). If cross-policy
  composition is ever needed, design `ref` (fine-grained result references)
  and `requires` (coarse policy dependencies) as one dependency feature:
  it needs a per-request results map, dependency-ordered evaluation with
  cycle detection, and defined semantics for referencing skipped, dry-run,
  filtered, or fail-fast-terminated policies. Cheaper alternatives that
  exist today: share condition logic via CUE packages at authoring time, or
  compose verdicts in CI by AND-ing `garmr eval` exit codes.

## Roadmap

Larger planned items (admission controller, CRDs/operator, Terraform
integration, policy linting, LSP/VS Code, result caching, OIDC/RBAC, HA)
live in `docs/src/content/docs/docs/project/roadmap.md`.
