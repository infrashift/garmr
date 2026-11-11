---
id: "01a1ca25-3796-7998-ac24-4a0dae882117"
title: "forEach allowMissing is opt-in"
type: "decision"
tags:
  - "engine"
  - "forEach"
  - "fail-closed"
  - "schema"
created: "2026-11-11T04:26:39-06:00"
timestamp: "2026-11-11T04:26:39-06:00"
description: "2026-11-11: an absent or null forEach list still fails by default; allowMissing: true treats it as empty, chosen over folding missing into allowEmpty, which would have failed open."
generated:
  by: "claude-code/opus-5.5"
  at: "2026-11-11T04:26:39-06:00"
---

# forEach allowMissing is opt-in

# forEach allowMissing is opt-in

## Problem

A probe against a real server found the following. A `forEach` over a list the input omits (Vizzini drops empty `risk_files` and `skipped`) **failed the rule**, and the message template came back with its alias placeholders unfilled (`{{r.path}}`). `allowEmpty` covered only a present-but-empty list (`internal/engine/eval.go`, `forEachNode.eval`). The workaround was `any: [{match: {path, exists: false}}, forEach…]` on every optional list.

## Decision (2026-11-11, user-approved)

- **New field `allowMissing?: bool`, default `false`.** When it is set, an absent path or a `null` value is treated as `[]`, and then `allowEmpty`, `where` and `count` decide as usual (a missing list counts 0). `null` is included because Go encoders emit `null` for nil slices.
- **Rejected: missing counts as empty under `allowEmpty`.** `allowEmpty` defaults to `true`, so every existing `forEach` over an absent field would have started to pass. That is a silent fail-open on misspelled paths, and on producers that stopped emitting a field.
- **Message fallback.** If a template names forEach elements but the rule fails with no failing element (missing or empty list, `mode: any` with no match, a `count` miss, or a sibling check failing), the engine's own reason is reported instead (for example `path 'risk_files' not found`). Other unresolved placeholders are still left as written.

Pinned by `TestOperators` (the absent/null/empty × allowMissing × allowEmpty/count/not matrix) and `TestMessage_AliasTemplateWithoutFailingElement`. Example: `foreach-optional` in `example-policies/advanced-operators/foreach.cue`.

Part of [Vizzini integration stays HTTP/JSON](./vizzini-integration-stays-http-json--01a1ca253787.md).
