# TODO — Recommended Feature Work

Feature gaps identified during the 2026-07 code/docs review. These were
deliberately **not** implemented on `feature/refactor` (that branch fixed bugs
and aligned docs); they are recorded here so the ideas aren't lost.

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
