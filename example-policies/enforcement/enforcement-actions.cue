// example-policies/enforcement/enforcement-actions.cue
// Demonstrates enforcement actions: deny, warn, audit
// Also showcases dry-run mode, exceptions, and fail-fast evaluation
package enforcement

// Deny enforcement — violations block the action (exit code 1 in CLI)
denyPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "enforce-deny"
		namespace: "enforcement"
	}
	spec: {
		description: "Deny enforcement — violations produce a 'deny' decision"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "ENF-001"
				description: "Production must have TLS enabled"
				severity:    "critical"
				expr: match: {
					path:   "spec.tls.enabled"
					equals: true
				}
				message: "TLS must be enabled — violation will DENY the request"
			},
		]
		enforcement: action: "deny"
	}
}

// Warn enforcement — violations produce warnings but don't block (exit code 0)
warnPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "enforce-warn"
		namespace: "enforcement"
	}
	spec: {
		description: "Warn enforcement — violations produce a 'warn' decision instead of 'deny'"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "ENF-002"
				description: "Services should have a description"
				severity:    "low"
				expr: match: {
					path:   "metadata.description"
					exists: true
				}
				message:     "missing description — this is a warning, not a blocking violation"
				remediation: "Add a metadata.description to improve documentation"
			},
			{
				id:          "ENF-003"
				description: "Should have at least 2 replicas for HA"
				severity:    "medium"
				expr: match: {
					path:               "spec.replicas"
					greaterThanOrEqual: 2
				}
				message: "fewer than 2 replicas — not highly available (warning only)"
			},
		]
		enforcement: action: "warn"
	}
}

// Audit enforcement — violations are logged but don't affect the decision
auditPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "enforce-audit"
		namespace: "enforcement"
	}
	spec: {
		description: "Audit enforcement — violations are recorded for reporting only"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "ENF-004"
				description: "Resource should have a cost-center label"
				severity:    "info"
				expr: match: {
					path:   "metadata.labels.costCenter"
					exists: true
				}
				message: "no cost-center label — audit finding for FinOps reporting"
			},
		]
		enforcement: action: "audit"
	}
}

// Dry-run mode — evaluates rules but downgrades deny to warn (prefixed with [DRY RUN])
// Useful for testing new policies in production without blocking deployments
dryRunPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "enforce-dry-run"
		namespace: "enforcement"
	}
	spec: {
		description: "Dry-run mode — deny is downgraded to warn with [DRY RUN] prefix"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "ENF-005"
				description: "New policy under evaluation — image must use digest"
				severity:    "high"
				expr: match: {
					path:    "spec.image.reference"
					pattern: "@sha256:[a-f0-9]{64}$"
				}
				message:     "image should use digest reference (sha256) instead of tag"
				remediation: "Reference images by digest: myapp@sha256:abc123..."
				category:    "security"
				tags: ["supply-chain", "experimental"]
			},
		]
		enforcement: {
			action: "deny"
			dryRun: true
		}
	}
}

// Exception handling — bypass enforcement for specific resources
// Exceptions support expiry dates, approval chains, and ticket references
exceptionPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "enforce-with-exceptions"
		namespace: "enforcement"
	}
	spec: {
		description: "Deny policy with exceptions for specific resources"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "ENF-006"
				description: "All services must use private registry"
				severity:    "critical"
				expr: match: {
					path:      "spec.image"
					hasPrefix: "registry.internal.example.com/"
				}
				message: "image must come from the internal registry"
			},
		]
		enforcement: {
			action: "deny"
			exceptions: [
				{
					name:   "legacy-monitoring"
					reason: "Legacy monitoring stack uses upstream images during migration"
					match: {
						kind:       "Pod"
						namespaces: ["monitoring"]
						labels: {
							"legacy": "true"
						}
					}
					expiry:     "2026-06-30T00:00:00Z"
					approvedBy: ["platform-lead@example.com", "security-team@example.com"]
					ticket:     "OPS-4521"
				},
				{
					name:   "ci-tooling"
					reason: "CI runners use upstream tool images"
					match: {
						kind:       "Pod"
						namespaces: ["ci"]
					}
					expiry: "2026-12-31T00:00:00Z"
					ticket: "PLAT-1234"
				},
			]
		}
	}
}

// Fail-fast evaluation — stop on first rule failure
// Useful for expensive evaluations or when the first failure is sufficient
failFastPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "enforce-fail-fast"
		namespace: "enforcement"
	}
	spec: {
		description: "Fail-fast evaluation — stops at the first rule failure"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "ENF-007"
				description: "Must have required metadata"
				severity:    "critical"
				priority:    10
				expr: match: {
					path:   "metadata.name"
					exists: true
				}
				message: "metadata.name is required — evaluation stopped (fail-fast)"
			},
			{
				id:          "ENF-008"
				description: "Must target a valid environment"
				severity:    "high"
				priority:    20
				expr: match: {
					path: "environment"
					in: ["development", "staging", "production"]
				}
				message: "invalid environment — evaluation stopped (fail-fast)"
			},
			{
				id:          "ENF-009"
				description: "Must have owner label"
				severity:    "medium"
				priority:    30
				expr: match: {
					path:   "metadata.labels.owner"
					exists: true
				}
				message: "missing owner label — this rule only runs if earlier rules passed"
			},
		]
		enforcement: action: "deny"
		evaluation: {
			order:    "priority"
			failFast: true
		}
	}
}
