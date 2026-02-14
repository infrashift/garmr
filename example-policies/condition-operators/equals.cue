// example-policies/condition-operators/equals.cue
// Demonstrates the match.equals operator for exact value matching
// Supports string, numeric, and boolean equality checks
package operators

// String equality — checks that a field exactly matches a string value
stringEqualsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "equals-string"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates exact string matching using the equals operator"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "EQ-001"
				description: "Environment must be production"
				severity:    "high"
				expr: match: {
					path:   "environment"
					equals: "production"
				}
				message: "environment must be 'production'"
			},
			{
				id:          "EQ-002"
				description: "Region must match expected value"
				severity:    "medium"
				expr: match: {
					path:   "metadata.region"
					equals: "us-east-1"
				}
				message: "region must be 'us-east-1'"
			},
		]
		enforcement: action: "deny"
	}
}

// Numeric equality — checks that a numeric field matches exactly
numericEqualsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "equals-numeric"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates exact numeric matching using the equals operator"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "EQ-003"
				description: "Replica count must be exactly 3"
				severity:    "medium"
				expr: match: {
					path:   "spec.replicas"
					equals: 3
				}
				message: "replicas must be exactly 3"
			},
		]
		enforcement: action: "warn"
	}
}

// Boolean equality — checks that a boolean field matches
boolEqualsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "equals-boolean"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates boolean field matching using the equals operator"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "EQ-004"
				description: "TLS must be enabled"
				severity:    "critical"
				expr: match: {
					path:   "spec.tls.enabled"
					equals: true
				}
				message:     "TLS must be enabled for all services"
				remediation: "Set spec.tls.enabled to true in your configuration"
			},
		]
		enforcement: action: "deny"
	}
}
