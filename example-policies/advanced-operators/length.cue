// example-policies/advanced-operators/length.cue
// Demonstrates the length expression for array and string length constraints
// Supports: equals, greaterThan, lessThan, min, max
package advanced

lengthPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "length-constraints"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Validates array and string lengths using various length operators"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "LEN-001"
				description: "Must have at least 1 container"
				severity:    "high"
				expr: match: {
					path:   "spec.containers"
					length: min: 1
				}
				message: "at least one container is required"
			},
			{
				id:          "LEN-002"
				description: "Must not exceed 5 containers"
				severity:    "medium"
				expr: match: {
					path:   "spec.containers"
					length: max: 5
				}
				message: "at most 5 containers are allowed per pod"
			},
			{
				id:          "LEN-003"
				description: "Must have exactly 3 availability zones"
				severity:    "low"
				expr: match: {
					path:   "spec.availabilityZones"
					length: equals: 3
				}
				message: "exactly 3 availability zones are required"
			},
			{
				id:          "LEN-004"
				description: "Service name must be at least 3 characters"
				severity:    "medium"
				expr: match: {
					path:   "metadata.name"
					length: greaterThan: 2
				}
				message: "service name must be at least 3 characters long"
			},
			{
				id:          "LEN-005"
				description: "Tags list must not be empty"
				severity:    "low"
				expr: match: {
					path:   "metadata.tags"
					length: greaterThan: 0
				}
				message:     "metadata.tags must contain at least one tag"
				remediation: "Add descriptive tags for resource classification"
				category:    "governance"
			},
		]
		enforcement: action: "warn"
	}
}
