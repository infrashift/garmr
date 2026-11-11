---
id: "01a1ca25-3787-7427-8b0d-1e6585f2e9fe"
title: "Vizzini integration stays HTTP/JSON"
type: "decision"
tags:
  - "vizzini"
  - "integration"
  - "api"
  - "grpc"
created: "2026-11-11T04:26:39-06:00"
timestamp: "2026-11-11T04:26:39-06:00"
description: "2026-11-11: garmr integrates with the Vizzini PR reviewer as a data contract over HTTP/JSON or in-process eval, not gRPC; six garmr changes on feature/improvements-for-vizzini support it."
generated:
  by: "claude-code/opus-5.5"
  at: "2026-11-11T04:26:39-06:00"
---

# Vizzini integration stays HTTP/JSON

# Vizzini integration stays HTTP/JSON

## Context

Vizzini is an LLM pull-request reviewer. Under its ADR-0010 the integration is a **data contract**: CI runs `pr-review`, which writes a JSON review report (CUE-typed `#ReviewReport`), and then `garmr eval` gates on it. Vizzini never calls garmr directly.

## Decision (2026-11-11)

**No gRPC.** The transport stays HTTP/JSON, and in-process evaluation is added for CI and offline use. The reasons:

- **Volume and latency.** There is one small report per review, and the LLM calls before it take seconds. Transport overhead does not matter.
- **The input is a document, not an RPC payload.** Protobuf would either wrap the document in an opaque `bytes`/`Struct` field or couple garmr to Vizzini's schema.
- **Dependencies.** gRPC would add `google.golang.org/grpc` and protobuf to Vizzini's pinned dependencies, which needs a new ADR on its side, for no gain over `net/http`.
- **Operability.** curl, proxies, ingress and the mesh all work with HTTP/JSON. gRPC needs HTTP/2 end to end and tools such as grpcurl.

gRPC would make sense only if garmr grows into high-throughput admission control, streaming evaluation, or generated typed clients for many languages. For stronger typing over HTTP, use `/openapi.json` and policy input schemas instead.

## The garmr changes it motivated (branch feature/improvements-for-vizzini)

1. `garmr eval --local --policy-dir <dir|file>` evaluates in-process. Its output is identical to the server's because both go through the shared `internal/api` converter. It runs with no server in CI or in offline microVMs.
2. [`forEach.allowMissing` is opt-in](./foreach-allowmissing-is-opt-in--01a1ca253796.md). Absent and null lists otherwise still fail. Alias message templates no longer come back unrendered.
3. Request-id correlation convention: `--request-id "<repo>#<pr>@<sha>"`, shared by the producer and garmr (docs: CI/CD guide, "Correlating decisions").
4. Structured findings: the rule declares `details: {file: "f.file", …}`, and each failing forEach element becomes `{path, index, details}` (capped at 100). Only the values the policy names are echoed back.
5. [`spec.inputSchema`, enforced at load time and by the CLI only](./inputschema-is-enforced-at-load-and-in-the-cli-not-per-request--01a1ca30fa83.md).
6. [Per-rule and per-finding exceptions](./exceptions-can-waive-rules-and-individual-findings--01a1ca3734c7.md) (finding fingerprints come from Vizzini).

Related: [Optional TLS reinstated](./optional-tls-reinstated--01a1984e4679.md) (same deployment model, non-mesh callers).
