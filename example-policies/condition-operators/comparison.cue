// example-policies/condition-operators/comparison.cue
// Demonstrates numeric comparison operators:
// greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual
package operators

numericBoundsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "numeric-comparison"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates numeric fields using comparison operators"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "CMP-001"
				description: "Replica count must be at least 2 for high availability"
				severity:    "high"
				expr: match: {
					path:               "spec.replicas"
					greaterThanOrEqual: 2
				}
				message:     "replicas must be >= 2 for high availability"
				remediation: "Increase spec.replicas to at least 2"
				category:    "availability"
			},
			{
				id:          "CMP-002"
				description: "Replica count must not exceed 10"
				severity:    "medium"
				expr: match: {
					path:            "spec.replicas"
					lessThanOrEqual: 10
				}
				message:  "replicas must be <= 10 to control costs"
				category: "cost"
			},
			{
				id:          "CMP-003"
				description: "CPU limit must be greater than 0"
				severity:    "high"
				expr: match: {
					path:        "spec.resources.cpu"
					greaterThan: 0
				}
				message: "CPU limit must be greater than 0"
			},
			{
				id:          "CMP-004"
				description: "Memory limit must be less than 8192 MB"
				severity:    "medium"
				expr: match: {
					path:     "spec.resources.memoryMB"
					lessThan: 8192
				}
				message: "memory limit must be less than 8192 MB"
			},
		]
		enforcement: action: "deny"
	}
}
