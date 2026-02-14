// example-policies/real-world/release-gate.cue
// Release promotion gate policy for CI/CD pipelines
// Ensures releases meet quality, security, and compliance gates before promotion
package realworld

releaseGatePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "release-gate"
		namespace: "release"
		labels: {
			pipeline: "promotion"
			stage:    "pre-release"
		}
	}
	spec: {
		description: "Validates release artifacts meet promotion requirements for DTAP pipeline"
		target: resources: [{kind: "Release"}]
		rules: [
			{
				id:          "REL-001"
				description: "Release version must be valid semver"
				severity:    "critical"
				priority:    10
				expr: match: {
					path:    "version"
					pattern: "^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9.]+)?(\\+[a-zA-Z0-9.]+)?$"
				}
				message:  "release version must follow semantic versioning (e.g., v1.2.3)"
				category: "compliance"
				tags: ["semver"]
			},
			{
				id:          "REL-002"
				description: "All tests must pass"
				severity:    "critical"
				priority:    20
				expr: all: [
					{match: {path: "quality.tests.unit.passed", equals: true}},
					{match: {path: "quality.tests.integration.passed", equals: true}},
					{match: {path: "quality.tests.e2e.passed", equals: true}},
				]
				message:     "all test suites (unit, integration, e2e) must pass"
				remediation: "Fix failing tests before promoting the release"
				category:    "quality"
				tags: ["testing"]
			},
			{
				id:          "REL-003"
				description: "Code coverage must be at least 80%"
				severity:    "high"
				priority:    25
				expr: match: {
					path:               "quality.coverage.percentage"
					greaterThanOrEqual: 80
				}
				message:     "code coverage must be >= 80%"
				remediation: "Add tests to increase coverage above the 80% threshold"
				category:    "quality"
				tags: ["coverage"]
			},
			{
				id:          "REL-004"
				description: "No critical or high vulnerabilities"
				severity:    "critical"
				priority:    30
				expr: all: [
					{match: {path: "security.vulnerabilities.critical", equals: 0}},
					{match: {path: "security.vulnerabilities.high", equals: 0}},
				]
				message:     "release must have zero critical and high vulnerabilities"
				remediation: "Remediate all critical and high vulnerabilities before release"
				category:    "security"
				tags: ["vulnerability-scanning", "slsa"]
			},
			{
				id:          "REL-005"
				description: "Build must have signed provenance"
				severity:    "high"
				priority:    35
				expr: all: [
					{match: {path: "provenance.signed", equals: true}},
					{match: {path: "provenance.buildPlatform", exists: true}},
				]
				message:  "release must have signed provenance with build platform info"
				category: "compliance"
				tags: ["slsa", "provenance"]
			},
			{
				id:          "REL-006"
				description: "Target environment must be valid DTAP stage"
				severity:    "high"
				priority:    5
				expr: match: {
					path: "targetEnvironment"
					in: ["development", "testing", "acceptance", "production"]
				}
				message:  "target environment must be a valid DTAP stage"
				category: "compliance"
			},
			{
				id:          "REL-007"
				description: "Approval is required for production releases"
				severity:    "critical"
				priority:    40
				expr: any: [
					// Non-production releases don't need approval
					{not: {match: {path: "targetEnvironment", equals: "production"}}},
					// Production releases must have approvals
					{all: [
						{match: {path: "approvals.count", greaterThanOrEqual: 2}},
						{match: {path: "approvals.leadApproved", equals: true}},
					]},
				]
				message:     "production releases require at least 2 approvals including a lead"
				remediation: "Obtain required approvals before promoting to production"
				category:    "compliance"
				tags: ["change-management"]
			},
		]
		enforcement: action: "deny"
		evaluation: {
			order:    "priority"
			failFast: true
		}
	}
}
