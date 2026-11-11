// Test suite for the review-gate policy. Run with:
//
//	garmr test example-policies/real-world/review-gate.cue
//
// Inputs are checked against the policy's spec.inputSchema before each case
// runs, so a fixture that drifts from the report contract fails here.

_cleanReview: {
	repository: "acme/api"
	pr:         482
	head_sha:   "3f9c2e1d8a7b"
	verdict:    "approve"
	risk_score: number | *2
}

policy: "review/review-gate"

tests: [
	{
		name:  "clean review without optional lists is allowed"
		input: _cleanReview
		expect: {
			decision:     "allow"
			noViolations: true
		}
	},
	{
		name: "major finding is denied"
		input: _cleanReview & {findings: [{file: "a.go", start_line: 3, severity: "major", title: "SQL built by concatenation", fingerprint: "aaaa"}]}
		expect: {
			decision: "deny"
			violations: [{id: "REV-001", messageContains: "a.go:3 major"}]
			violationCount: 1
		}
	},
	{
		name: "waived finding is allowed"
		input: _cleanReview & {findings: [{file: "internal/cache/key.go", start_line: 41, severity: "major", title: "MD5 used for hashing", fingerprint: "9f2c41e0b7d3"}]}
		expect: decision: "allow"
	},
	{
		name: "high risk score is denied"
		input: _cleanReview & {risk_score: 8}
		expect: {
			decision: "deny"
			violations: [{id: "REV-002"}]
		}
	},
	{
		name: "report that breaks the contract is an error"
		input: _cleanReview & {risk_scor: 1}
		expect: error: true
	},
]
