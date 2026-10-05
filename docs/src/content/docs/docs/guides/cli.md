---
title: "CLI Reference"
description: "Complete command reference for the Garmr CLI"
sidebar:
  order: 0
  label: "CLI Reference"
---

Complete command reference for the Garmr CLI.

`eval`, `policy list/get/delete/reload`, and `health` are REST clients and require a running Garmr server. `validate`, `test`, `docs generate`, and `policy digest/lock/validate-lock/diff` run locally without a server — `validate` and `policy digest` embed the exact engine loader the server runs, so their results predict what the server will load.

The CLI has no authentication or TLS client options and cannot talk to an API-key-protected server. Run the CLI against the server over a trusted network (localhost, cluster-internal), or behind a service mesh sidecar that handles mTLS — the same deployment model the server's `auth.identity_header` support is designed for.

## Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | | Config file path (env: `GARMR_CONFIG`) | `~/.garmr.yaml`, then `./.garmr.yaml` |
| `--server` | | Garmr server URL | `http://localhost:8080` |
| `--output` | `-o` | Output format (table, json, yaml) | `table` |
| `--quiet` | `-q` | Suppress non-essential output | `false` |
| `--verbose` | `-v` | Verbose output (see per-command docs for exact effect) | unset |

## Exit Codes

Every command uses the same three codes, so CI can tell "the answer is no"
from "there is no answer":

| Code | Meaning |
|------|---------|
| 0 | Success: allow or warn, valid, tests passed, healthy, reload converged |
| 1 | A negative result: deny, an invalid policy, a failed test, a lock-file mismatch, an unhealthy server, a failed or unconverged reload |
| 2 | The command could not run: bad flags or arguments, unreadable `eval` input, a policy or test suite that fails to load (`test`, `policy digest`), or a server that is unreachable or answers with an error (`eval`, `policy list/get/delete`) |

Fail the build on `1`; retry or alert on `2`. Three commands report an
unreachable server as `1`, because for them it is the answer: `health`
(the server is not healthy), `policy reload` (that instance did not
reload), and `validate --remote` (the file was not validated).

---

## Commands

### garmr eval

Evaluate input against policies.

```bash
garmr eval --input <file> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input file (`-` for stdin). One of `--input` or `--data` is required. | |
| `--data` | `-d` | Inline JSON/YAML data | |
| `--format` | `-f` | Input format (json, yaml, auto) | `auto` |
| `--policy` | `-p` | Specific policies to evaluate (repeatable): `namespace/name`, or a bare `metadata.name` resolved inside `--namespace` (`default` when it is unset). A qualified name ignores `--namespace`. | |
| `--namespace` | `-n` | Policy namespace to evaluate (single value) | |
| `--request-id` | | Request ID for audit correlation | |
| `--verbose` | `-v` | Show rule details. Default shows details on fail, hides on pass. `--verbose=false` always hides. | unset |

**Examples:**

```bash
# Basic evaluation
garmr eval --input deployment.json

# Filter by namespace (single namespace per invocation)
garmr eval --input deployment.json -n security

# Evaluate one named policy: namespace/name, or a bare name plus -n
garmr eval --input deployment.json -p security/container-security
garmr eval --input deployment.json -n security -p container-security

# JSON output for CI/CD
garmr eval --input deployment.json -o json

# With request ID for audit correlation
garmr eval --input deployment.json --request-id "gh-$GITHUB_RUN_ID"

# From stdin
cat deployment.json | garmr eval --input -

# Include all rules (passed and failed)
garmr eval --input deployment.json --verbose

# Suppress rule details even on failure (show only the decision)
garmr eval --input deployment.json --verbose=false
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | ALLOW or WARN - Nothing blocked the evaluation |
| 1 | DENY - A deny-enforced policy failed |
| 2 | The evaluation did not run: server unreachable, a `4xx`/`5xx` from the server, unreadable input, bad flags |

A deny and an outage have different exit codes, so a CI step can fail the
build on `1` and retry or alert on `2` without parsing the output.

Warn is advisory by design, so `garmr eval` exits `0` on warn decisions.
If a team needs warnings to gate CI, change the policy's
`enforcement.action` from `warn` to `deny` — the decision lives in
version control where it can be reviewed, rather than in a CLI flag.

**Fail-closed on no match:**

If an evaluation matches zero policies — because the namespace doesn't
exist, the named policy isn't loaded, the server has no policies at all,
or nothing targets the input — Garmr returns **DENY** (exit code 1) with
a synthetic result that tells you which of those cases applied. This is
the default behavior and is deliberate: a silent ALLOW on no match would
hide typos in `--namespace`, missing policy files, or forgotten loads,
giving a false sense of safety.

Example output when `--namespace` doesn't match any loaded policy:

```
Decision: ✗ DENY

SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
----------------------------------------------------------------------------------------------------
HIGH         __system__/policy-match        FAIL       no-match No policies found in namespace "release".
                                                                ↳ Verify the namespace and policy names...
```

To restore the legacy fail-open behavior (not recommended), set in your
server config:

```yaml
evaluation:
  require_match: false
```

or pass `--require-match=false` to `garmr-server`.

---

### garmr validate

Validate policies locally with the same schema and loader the server uses at startup — no server required. A green result means the server will load the set. Directories are loaded as CUE packages, so multi-file policy packages (shared definitions + policies) validate correctly. On success the policy-set digest is printed for convergence checks.

```bash
garmr validate <file-or-dir> [file-or-dir...] [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--remote` | Validate via a running server's `/v1/validate` instead of locally (compiles each file in isolation) | `false` |

Exits `0` when every input is valid and `1` otherwise.

**Examples:**

```bash
# Validate a policy tree locally (CI gate)
garmr validate policies/

# Validate a single file
garmr validate policies/security.cue

# Validate against a running server
garmr validate --remote --server http://garmr:8080 policies/security.cue
```

---

### garmr policy

Policy management commands.

#### garmr policy list

List loaded policies.

```bash
garmr policy list [flags]
```

**Flags:**

| Flag | Short | Description |
|------|-------|-------------|
| `--namespace` | `-n` | Filter by namespace |

**Examples:**

```bash
# List all policies
garmr policy list

# List as JSON
garmr policy list -o json

# Filter by namespace
garmr policy list -n security
```

The table ends with a `Digest:` line: the server's policy-set digest, the
same value `garmr policy digest` computes locally. `-o json` prints the raw
`GET /v1/policies` body: `{"policies": [...], "digest": ..., "instance_id": ...}`,
so select policies with `jq '.policies[]'`.

#### garmr policy get

Get a policy by name.

```bash
garmr policy get <name> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--namespace` | `-n` | Policy namespace | `default` |

#### garmr policy delete

Delete a policy from the server's memory.

:::caution
This removes the policy from the **one** instance that receives the request.
Other instances keep serving it, and the next reload or restart brings it
back everywhere. To remove a policy permanently, delete it from the policy
source (git) and deploy.
:::

```bash
garmr policy delete <name> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--namespace` | `-n` | Policy namespace | `default` |
| `--force` | | Skip confirmation | `false` |

#### garmr policy digest

Load policies locally exactly as the server does and print the
deterministic policy-set digest. Runs locally (no server needed).

```bash
garmr policy digest <policy-dir|policy-file>
```

Compare the result with the `digest` field of `GET /v1/policies`, or of a
reload response, to verify that a server converged on exactly the content
that was shipped. Exits `2` if the policies fail to load.

```bash
# Digest of the checkout
garmr policy digest policies/

# What one server is actually serving
curl -s http://garmr:8080/v1/policies | jq -r .digest

# Reload every instance and require that digest
garmr policy reload --servers http://10.0.0.11:8080,http://10.0.0.12:8080 \
  --expect-digest "$(garmr policy digest policies/)"
```

#### garmr policy reload

Reload policies from disk on one or more instances. The reload endpoint
mutates a single server process — behind a load balancer or mesh, pass
every instance via `--servers`, or use `--converge`, so all of them
converge. Exits `1` if any instance fails, if `--expect-digest` doesn't
match, or if instances end up with diverging digests.

```bash
garmr policy reload [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--servers` | Reload every listed instance (comma-separated or repeated) | the `--server` address |
| `--expect-digest` | Fail unless every instance reports this policy-set digest | |
| `--converge` | Repeat the reload against one address until `--instances` distinct instances have acknowledged | `false` |
| `--instances` | Number of distinct instances to converge (required with `--converge`) | |
| `--converge-timeout` | Give up if `--converge` has not reached every instance in this long | `2m` |

Use `--servers` when you can address instances directly. Behind a service-mesh
upstream you cannot — every call load-balances and there is only one address —
so `--servers` would reload one arbitrary instance, see a single digest, and
exit 0 with the rest of the fleet stale. `--converge` handles that case: each
response carries an `instance_id`, and the command keeps reloading until it has
seen `--instances` distinct instances all reporting the expected digest,
failing on timeout, digest mismatch, or divergence. `--converge` takes exactly
one address (combining it with several `--servers` is an error), and it
fails if the server does not report an `instance_id`.

`instance_id` is the server's `NOMAD_ALLOC_ID`, else `NOMAD_SHORT_ALLOC_ID`,
else `<hostname>:<pid>` (the `HOSTNAME` variable, or the OS hostname, plus
the process ID), so two processes on one host are distinct instances.

**Examples:**

```bash
# Reload the single configured instance
garmr policy reload

# Through a mesh upstream that load-balances (e.g. Consul Connect)
garmr policy reload --server http://localhost:8080 \
  --converge --instances 2 \
  --expect-digest "$(garmr policy digest policies/)"

# Fan out to every instance with convergence enforced
garmr policy reload \
  --servers http://10.0.0.11:8080,http://10.0.0.12:8080 \
  --expect-digest "$(garmr policy digest policies/)"

# Machine-readable result
garmr policy reload -o json
```

**JSON output (`-o json`)** has three shapes:

```jsonc
// One address that answered: the bare server response
{
  "success": true,
  "policies_loaded": 45,
  "digest": "907537ab...bdf7e8dd",
  "reload_time_ms": 183,
  "storage_type": "filesystem",
  "instance_id": "8f3c2a1e-alloc"
}

// --servers with several addresses: one entry per address
[
  {"server": "http://10.0.0.11:8080", "result": {"success": true, "digest": "907537ab...", "...": "..."}},
  {"server": "http://10.0.0.12:8080", "error": "making request: ... connection refused"}
]

// --converge
{
  "server": "http://localhost:8080",
  "converged": true,
  "instances_wanted": 2,
  "instances_seen": ["8f3c2a1e-alloc", "b21d9e07-alloc"],
  "digest": "907537ab...bdf7e8dd",
  "attempts": 3
}
```

In the list, an entry has `result`, `error`, or both (a digest mismatch
reports the result alongside the error). A single address whose call failed
outright (connection refused, non-`200`) also uses the list shape. With a
single address, an `--expect-digest` mismatch prints the bare response with
the mismatch in its `"error"` field; `"success"` stays `true` because the
server did reload, just not to the expected digest, and the command exits 1.
The `--converge` report adds `"error"` when it fails.

#### garmr policy lock

Generate a lock file for a policy. Runs locally (no server needed).

```bash
garmr policy lock <file> [file...] [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--version` | Version to record in lock file |
| `--recursive` | Process directories recursively |
| `--updated-by` | Override the `updatedBy` field |

**Examples:**

```bash
# Generate lock file
garmr policy lock policies/release-gate.cue --version 1.0.0

# Creates: policies/release-gate.cue.lock
```

#### garmr policy validate-lock

Validate policy against its lock file. Runs locally (no server needed). Accepts files and directories; directories are always expanded recursively.

```bash
garmr policy validate-lock <file-or-dir> [file-or-dir...]
```

Exits `0` when every policy matches its lock file and `1` otherwise
(including a missing lock file), so it can gate CI. Exits `2` when the
arguments contain no policy files at all.

**Examples:**

```bash
# Validate single policy
garmr policy validate-lock policies/release-gate.cue

# Validate all policies in a directory (recursive)
garmr policy validate-lock policies/
```

#### garmr policy diff

Show differences between policy and lock file. Runs locally (no server needed). It is informational: it exits `0` whether the policy is in sync or not — gate on `validate-lock` instead.

```bash
garmr policy diff <file>
```

**Examples:**

```bash
# Check if policy has changed
garmr policy diff policies/release-gate.cue
```

---

### garmr test

Run policy tests. Runs locally (no server needed) using the same evaluation
engine as the server, so test results match server decisions exactly. Takes
positional policy/test paths; test suites live in `*_test.cue` files next to
the policy files they test (see `example-policies/real-world/release-gate_test.cue`
for a complete example).

A suite names the policy under test — by `metadata.name`, or
`"namespace/name"` if the name is ambiguous across loaded files — and each
test provides an `input` plus an `expect` block (`decision`, `violations`
by rule ID with optional `severity`/`messageContains`, `noViolations`,
`violationCount`). Inputs that the policy's target does not match fail
closed and surface a `no-match` violation explaining why.

```bash
garmr test <policy-file> [test-file] [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--verbose` | `-v` | Show detailed output (the global flag) | `false` |
| `--recursive` | `-r` | Process directories recursively | `false` |
| `--filter` | | Filter tests by name | |
| `--format` | | Output format (text, json, tap) — deliberately not `-o`, which is the root output flag | `text` |
| `--fail-fast` | | Stop on first failure | `false` |

Exits `0` when every test passes, `1` when any test fails, and `2` when no
suite is found or a policy or suite can't be loaded.

**Examples:**

```bash
# Run tests for a policy
garmr test policies/release-gate.cue

# Run all tests in directory
garmr test policies/ --recursive

# Filter by test name
garmr test policies/ --filter "valid release"

# TAP output for CI
garmr test policies/ --format tap

# JSON output
garmr test policies/ --format json

# Verbose output
garmr test policies/ -v
```

**Test File Format:**

```cue
// policies/release-gate_test.cue
{
    policy: "release-gate"

    tests: [{
        name: "valid release passes"
        input: {
            kind: "release"
            version: "1.0.0"
            tests: {passed: true}
        }
        expect: {
            decision: "allow"
            noViolations: true
        }
    }, {
        name: "missing tests fails"
        input: {
            kind: "release"
            version: "1.0.0"
        }
        expect: {
            decision: "deny"
            violations: [{id: "REL-001"}]
        }
    }]
}
```

---

### garmr docs

Documentation generation commands.

#### garmr docs generate

Generate markdown documentation from policies. Runs locally (no server needed).

```bash
garmr docs generate <policy-dir> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--format` | `-f` | Output format (only `generic-markdown` is currently supported) | `generic-markdown` |
| `--out-dir` | | Output directory | `./docs/policies` |
| `--recursive` | `-r` | Process recursively | `true` |

**Examples:**

```bash
# Generate docs from examples
garmr docs generate ./example-policies --out-dir ./out/docs

# Specify format
garmr docs generate ./policies --format generic-markdown --out-dir ./docs
```

---

### garmr health

Check server health.

```bash
garmr health [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--wait` | Wait for server to be ready | `false` |
| `--timeout` | Timeout when waiting | `30s` |

Calls the server's `/health` endpoint. Exits `0` when the server answers
healthy and `1` when it is unreachable or reports unhealthy (with
`--wait`, `1` once `--timeout` passes without a healthy answer), whatever
the output format. A malformed `--server` address exits `2`.

**Examples:**

```bash
# Check health
garmr health

# JSON output
garmr health -o json
```

---

### garmr version

Show version information, including the Go runtime version and platform the binary was built with.

```bash
garmr version
```

---

## Environment Variables

Three settings can be set via environment variables. Other flags
(`--quiet`, `--verbose`, and every per-command flag) have no environment
equivalent.

| Variable | Flag |
|----------|------|
| `GARMR_SERVER` | `--server` |
| `GARMR_OUTPUT` | `--output` |
| `GARMR_CONFIG` | `--config` |

**Example:**

```bash
export GARMR_SERVER=https://garmr.example.com:8080
export GARMR_OUTPUT=json

garmr eval --input deployment.json
```

---

## Configuration File

Create `~/.garmr.yaml` or `./.garmr.yaml` (the file name is `.garmr.yaml`
in both locations), or point `--config` / `GARMR_CONFIG` at any path:

```yaml
server: "http://localhost:8080"
output: "table"
```

---

## Output Formats

### Table (default)

Human-readable table format:

```
Decision: ✗ DENY

SEVERITY     POLICY/RULE                    RESULT     ID       MESSAGE
----------------------------------------------------------------------------------------------------
CRITICAL     security/container-security    FAIL       SEC-001  containers must set securityContext.r...
                                                                 ↳ Set securityContext.runAsNonRoot: true and specify a non-root runAsUser
MEDIUM       security/container-security    FAIL       SEC-006  containers should use a read-only roo...
                                                                 ↳ Set securityContext.readOnlyRootFilesystem: true and use volume mounts for writable paths

Evaluated 1 policies, 6 rules in 98.962µs
```

Messages are truncated to fit the column; `↳` lines carry each failure's
remediation.

### JSON

Machine-readable JSON — the full `/v1/evaluate` response (see the
[REST API reference](/garmr/docs/guides/rest-api/#post-v1evaluate) for every field):

```json
{
  "decision": "deny",
  "request_id": "abc-123",
  "results": [
    {
      "policy_name": "container-security",
      "policy_namespace": "security",
      "rule_id": "SEC-001",
      "description": "Containers must assert runAsNonRoot",
      "severity": "critical",
      "passed": false,
      "message": "containers must set securityContext.runAsNonRoot: true",
      "remediation": "Set securityContext.runAsNonRoot: true and specify a non-root runAsUser"
    }
  ],
  "metrics": {
    "evaluation_time_ns": 59524,
    "policies_evaluated": 1,
    "rules_evaluated": 6
  },
  "summary": {
    "total_rules": 6,
    "passed": 5,
    "failed": 1,
    "skipped": 0
  },
  "evaluation_mode": {
    "dry_run": false,
    "fail_fast": false,
    "short_circuited": false,
    "total_rules_in_scope": 6,
    "rules_evaluated": 6,
    "rules_skipped": 0
  },
  "terminated_early": false
}
```

`termination_rule` is added when fail-fast stopped the evaluation.

### YAML

A compact YAML summary — the decision and, per result, the rule ID, outcome,
message, and remediation. It is not the full response; use `-o json` when
you need policy names, severities, or the summary counts.

```yaml
decision: deny
results:
  - rule_id: SEC-001
    passed: false
    message: containers must set securityContext.runAsNonRoot: true
    remediation: Set securityContext.runAsNonRoot: true and specify a non-root runAsUser
```

---

## Examples with Test Data

```bash
# Start server (builds, then serves ./example-policies on :8080)
make dev

# Basic evaluation
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json

# Security policies only
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -n security

# Release pipeline gates
garmr eval --input testdata/real-world/release-pass.json -n release

# Failing evaluations
garmr eval --input testdata/real-world/k8s-pod-security-context-fail.yml -n security
garmr eval --input testdata/advanced-operators/compare-fail.yaml -n advanced-operators

# JSON output
garmr eval --input testdata/real-world/k8s-pod-security-context-pass.json -o json | jq '.decision'

# List policies
garmr policy list
garmr policy list -n security

# Generate documentation
garmr docs generate ./example-policies --out-dir ./out/docs
```
