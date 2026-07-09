// Test suite for the release-gate policy. Run with:
//
//	garmr test example-policies/real-world/release-gate.cue
//
// Note: no package clause — test files are not part of the policy package,
// so the server's policy-directory loader ignores them.

// _compliantRelease is a fully compliant input. Fields that individual
// tests override are declared with defaults (`| *value`), so a test can
// unify in a different concrete value to trip a specific rule.
_compliantRelease: {
	kind:       "Release"
	apiVersion: "release.garmr.io/v1"
	metadata: name:    "my-service"
	version:           string | *"v1.2.3"
	targetEnvironment: string | *"production"
	quality: {
		tests: {
			unit: passed:        bool | *true
			integration: passed: bool | *true
			e2e: passed:         bool | *true
		}
		coverage: percentage: 92
	}
	security: vulnerabilities: {
		critical: int | *0
		high:     int | *0
	}
	provenance: {
		signed:        true
		buildPlatform: "github-actions"
	}
	approvals: {
		count:        int | *2
		leadApproved: bool | *true
	}
}

policy: "release/release-gate"

tests: [
	{
		name:  "compliant release is allowed"
		input: _compliantRelease
		expect: {
			decision:     "allow"
			noViolations: true
		}
	},
	{
		name: "invalid version string is denied"
		input: _compliantRelease & {version: "not-a-version"}
		expect: {
			decision: "deny"
			violations: [{id: "REL-001", severity: "critical"}]
		}
	},
	{
		name: "failing unit tests are denied"
		input: _compliantRelease & {quality: tests: unit: passed: false}
		expect: {
			decision: "deny"
			violations: [{
				id:              "REL-002"
				messageContains: "test suites"
			}]
			violationCount: 1
		}
	},
	{
		name: "critical vulnerabilities are denied"
		input: _compliantRelease & {security: vulnerabilities: critical: 2}
		expect: {
			decision: "deny"
			violations: [{id: "REL-004", severity: "critical"}]
		}
	},
	{
		name: "unapproved production release is denied"
		input: _compliantRelease & {approvals: count: 1}
		expect: {
			decision: "deny"
			violations: [{id: "REL-007"}]
		}
	},
	{
		name: "staging release does not require approvals"
		input: _compliantRelease & {
			targetEnvironment: "staging"
			approvals: count:  0
		}
		expect: decision: "allow"
	},
	{
		name: "non-Release input fails closed as no-match"
		input: {
			kind: "Pod"
			metadata: name: "web"
		}
		expect: {
			decision: "deny"
			violations: [{
				id:              "no-match"
				messageContains: "target"
			}]
		}
	},
]
