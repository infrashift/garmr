---
id: "01a1ca30-fa83-7d5a-826f-3f599b97e218"
title: "inputSchema is enforced at load and in the CLI, not per request"
type: "decision"
tags:
  - "engine"
  - "schema"
  - "cue"
  - "performance"
  - "inputSchema"
created: "2026-11-11T04:39:29-06:00"
timestamp: "2026-11-11T04:39:29-06:00"
description: "2026-11-11: spec.inputSchema checks rule paths at every policy load and validates input only in garmr eval --local and garmr test; the server never compiles CUE per request."
generated:
  by: "claude-code/opus-5.5"
  at: "2026-11-11T04:39:29-06:00"
---

# inputSchema is enforced at load and in the CLI, not per request

# inputSchema is enforced at load and in the CLI, not per request

## Problem

Rule paths were only parsed for syntax. A misspelled field (`risk_scor`), or a list the producer renamed, loaded cleanly and produced a rule that could never pass, or under `not` could never fail. This was deferred as OPA-parity item #2 in TODO.md. Vizzini's report contract is already a CUE definition (`#ReviewReport`), so a policy can name it.

## Decision (2026-11-11, user-approved)

`spec.inputSchema?: _` holds a CUE definition, usually imported (`report.#ReviewReport`). It is used in two places:

1. **At every load.** The expression compiler records every input path resolved to the input root. An alias path `f.file` inside `forEach` over `findings` becomes `findings[*].file`. This covers expr, when, where, compare and func operands, message placeholders and `details`. `schemaPathChecker` reports only what the schema definitely rules out: a field a closed struct does not `Allows`, or a step into a scalar or a non-list. Open shapes (`_`, `{...}`, `[string]: T`, disjunctions it cannot follow) accept the rest of the path, so there are no false positives. This runs at server startup and reload, in `garmr validate` and in `/v1/validate`.
2. **The input itself, only for callers that opt in** (`EvaluateOptions.CheckInputSchema`): `garmr eval --local` and the `garmr test` runner. A violation is `ErrInvalidInput`, a distinct verdict (exit 2), not a deny.

**Rejected: validating every server request.** That means compiling CUE per evaluation, or a pool of contexts (the replica pool that was removed on 2026-10-03). It would undo the CUE-free evaluator that makes garmr 8–28× faster than OPA. See TODO.md, "CUE-free evaluator and schema tightening (2026-10-03)".

## Implementation notes worth knowing

- Compiled policies still keep **no `cue.Value`**. The schema is stored as self-contained CUE source via `Syntax(Definitions, InlineImports, Optional, Patterns)`. That output keeps closedness through a `_#def` embedding, and the load proves it recompiles alone.
- The input is checked through **JSON bytes, not `ctx.Encode`**. Encode turns the decoded `float64(3)` into a CUE float, which fails `int` fields.
- `LookupPath` does not see optional fields. `lookupField` falls back to `sel.Optional()`, then `cue.AnyString` (patterns).
- The spec decoder (`marshalSpec`) skips `inputSchema`, because a type cannot be rendered as JSON. The policy hash covers the schema.
- Imports resolve through the policy repo's `cue.mod` with no network access. The recommended approach is an in-repo (copied or synced, pinned) schema package. A registry fetch at load is discouraged because it breaks offline loads.

Part of [Vizzini integration stays HTTP/JSON](./vizzini-integration-stays-http-json--01a1ca253787.md). Sibling decision: [forEach allowMissing is opt-in](./foreach-allowmissing-is-opt-in--01a1ca253796.md).
