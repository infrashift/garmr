---
id: "01a1ca37-34c7-721a-ba8d-d0de6749f104"
title: "Exceptions can waive rules and individual findings"
type: "decision"
tags:
  - "engine"
  - "exceptions"
  - "waiver"
  - "fail-closed"
  - "schema"
created: "2026-11-11T04:46:18-06:00"
timestamp: "2026-11-11T04:46:18-06:00"
description: "2026-11-11: exceptions gained rules (skip named rules) and findings {as, where} (waive forEach elements, e.g. by producer fingerprint); waived elements are always reported, and a failing selector waives nothing."
generated:
  by: "claude-code/opus-5.5"
  at: "2026-11-11T04:46:18-06:00"
---

# Exceptions can waive rules and individual findings

# Exceptions can waive rules and individual findings

## Problem

Exceptions could only skip a **whole policy**, for inputs a resource selector matched. Accepting one specific finding ("this Major finding in the review report is accepted") meant disabling the whole gate. Per-rule exceptions were deferred as OPA-parity item #1 in TODO.md.

## Decision (2026-11-11, user-approved)

`#Exception` has three forms:

| Form | Waives | `match` |
|---|---|---|
| no `rules` | the whole policy (unchanged) | required, and must narrow |
| `rules: [...]` | those rules (out of scope, like a category filter) | optional |
| `rules` + `findings: {as, where}` | elements of the listed rules' forEach with alias `as` for which `where` holds | optional |

Design rules and their reasons:

- **Waived elements are skipped exactly like `where`-excluded ones.** They are not checked or counted, which gives uniform semantics for `all`/`any`/`count`. The waiver check runs after the forEach's own `where`.
- **A waiver is never silent.** Waived elements are reported under `waived` (path, details, exception name). A rule with waived elements is reported even when it passes and `include_passed` is off.
- **Fail closed.** A `where` that errors or fails waives nothing. Load rejects a rule id that does not exist, `findings` without `rules`, and a `findings.as` alias that no listed rule binds, because each of those would silently waive nothing or too much. Waiver `where` paths are checked against [inputSchema](./inputschema-is-enforced-at-load-and-in-the-cli-not-per-request--01a1ca30fa83.md).
- **Garmr does not compute fingerprints.** The producer (Vizzini) supplies a stable fingerprint per finding: a hash of file, rule, title and normalized line content. Garmr matches it with existing operators (`match: {path: "f.fingerprint", in: [...]}`). Waivers live in policy source, so each one is git-reviewed.
- `ExceptionSpec.Match` became a pointer. A zero `ResourceSelector` has `apiGroup ""`, which means the *core group*, not "anything". So an omitted `match` would have silently matched only core-group inputs.

Still deferred: per-rule `action` overrides.

Worked example: `example-policies/real-world/review-gate.cue`, which has a `_test.cue` suite. `TestExampleSuites` now runs every example suite.

Part of [Vizzini integration stays HTTP/JSON](./vizzini-integration-stays-http-json--01a1ca253787.md).
