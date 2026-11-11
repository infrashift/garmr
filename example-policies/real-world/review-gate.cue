// example-policies/real-world/review-gate.cue
// Merge gate over an automated code review report.
//
// A code reviewer writes a JSON report of its findings for each pull
// request; CI then runs `garmr eval` on that report. This policy shows the
// features built for that kind of producer-owned input:
//
//   inputSchema   the report's CUE definition. Every path below is checked
//                 against it when the policy loads, and `garmr eval --local`
//                 / `garmr test` reject a report that does not conform.
//   allowMissing  the reviewer omits `findings` and `skipped` when empty.
//   details       each failing finding is reported with its file and line,
//                 so CI can annotate the exact line.
//   exceptions    a specific finding is waived by its fingerprint, a stable
//                 hash the reviewer computes from file, rule, title and the
//                 normalized line, so the waiver survives unrelated edits.
//
// In a real repository the schema would be imported from the reviewer's CUE
// package (see "Importing input schemas" in the policy-loading docs); it is
// inlined here to keep the example self-contained.
package realworld

#ReviewFinding: {
	file:         string
	start_line?:  int
	end_line?:    int
	severity:     "critical" | "major" | "minor" | "nit"
	title:        string
	fingerprint?: string
}

#CodeReviewReport: {
	kind?:      "CodeReviewReport"
	repository: string
	pr:         int
	head_sha:   string
	verdict:    "approve" | "request_changes" | "comment"
	risk_score: number & >=0 & <=10
	findings?: [...#ReviewFinding]
	risk_files?: [...{path: string, score: number}]
	skipped?: [...{name: string, reason?: string}]
}

reviewGatePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "review-gate"
		namespace: "review"
		labels: team: "platform"
	}
	spec: {
		description: "Blocks a merge on serious review findings or high risk"
		inputSchema: #CodeReviewReport
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "REV-001"
				description: "No critical or major findings"
				severity:    "high"
				expr: forEach: {
					path:         "findings"
					as:           "f"
					allowMissing: true
					condition: not: match: {path: "f.severity", in: ["critical", "major"]}
				}
				message: "{{f.file}}:{{f.start_line}} {{f.severity}}: {{f.title}}"
				details: {file: "f.file", line: "f.start_line", severity: "f.severity", fingerprint: "f.fingerprint"}
				remediation: "Fix the finding, or add a reviewed exception for its fingerprint"
				category:    "review"
			},
			{
				id:          "REV-002"
				description: "Overall risk score must stay below 7"
				severity:    "high"
				expr: match: {path: "risk_score", lessThan: 7}
				message:  "risk score {{risk_score}} is 7 or higher"
				category: "review"
			},
			{
				id:          "REV-003"
				description: "No single file may be scored 8 or higher"
				severity:    "medium"
				expr: forEach: {
					path:         "risk_files"
					as:           "r"
					allowMissing: true
					condition: match: {path: "r.score", lessThan: 8}
				}
				message: "{{r.path}} has risk score {{r.score}}"
				details: {file: "r.path", score: "r.score"}
				category: "review"
			},
			{
				id:          "REV-004"
				description: "Every skipped check gives a reason"
				severity:    "low"
				expr: forEach: {
					path:         "skipped"
					as:           "s"
					allowMissing: true
					condition: match: {path: "s.reason", exists: true}
				}
				message:  "skipped check {{s.name}} gives no reason"
				category: "review"
			},
		]
		enforcement: {
			action: "deny"
			exceptions: [{
				name:   "accepted-legacy-crypto"
				reason: "Known MD5 use for cache keys, not security; replacement tracked"
				ticket: "SEC-1042"
				approvedBy: ["security-team"]
				rules: ["REV-001"]
				findings: {
					as: "f"
					where: match: {path: "f.fingerprint", in: ["9f2c41e0b7d3"]}
				}
			}]
		}
	}
}
