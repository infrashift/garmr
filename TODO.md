# TODO — Recommended Feature Work

Feature gaps identified during the 2026-07 code/docs reviews. These were
deliberately **not** implemented (the review branches fixed bugs, removed
debt, and aligned docs); they are recorded here so the ideas aren't lost.

Two rounds are recorded: `feature/refactor` (2026-07-08/09) and
`feature/review-fix-refactor` (2026-07-28).

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

## Engine — deferred cleanups (added 2026-07-28)

3. Directory loads do not validate against the embedded schema.
   `LoadPolicy` unifies the source with `#Policy` before compiling, but
   `loadInstancesIntoReplica` calls `compilePolicy` directly, so policies
   loaded from `--policy-dir` — the production path — are never schema
   checked. Explicit compile-time rejections cover the fields that mattered
   (see "Silently-ignored policy schema fields" below), but the general gap
   remains. Closing it means unifying in the directory loader too, which
   will start rejecting policies that load today; worth a deliberate
   migration rather than a silent tightening.
4. A policy that fails to compile during a directory load is skipped with a
   warning, and the surfaced error is "no policies found in <dir>" rather
   than the real reason. The fail-closed outcome is right; the diagnostic is
   not.

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
  `deploy/helm/garmr/examples/consul-connect/`). The server keeps plain
  server-side TLS (`tls.cert`/`tls.key`) for non-mesh deployments.
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
