// example-policies/advanced-operators/compare.cue
// Demonstrates the compare expression for cross-field and computed comparisons
// Compare uses left/op/right with values resolved from: path, literal, func
package advanced

// Cross-field comparison — comparing two input fields against each other
crossFieldPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "compare-cross-field"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Compares two fields from the input against each other"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "CMP-101"
				description: "Max replicas must be greater than min replicas"
				severity:    "high"
				expr: compare: {
					left: {path: "spec.autoscaling.maxReplicas"}
					op: ">"
					right: {path: "spec.autoscaling.minReplicas"}
				}
				message: "maxReplicas must be greater than minReplicas"
			},
			{
				id:          "CMP-102"
				description: "Memory limit must be >= memory request"
				severity:    "high"
				expr: compare: {
					left: {path: "spec.resources.memoryLimit"}
					op: ">="
					right: {path: "spec.resources.memoryRequest"}
				}
				message: "memory limit must be >= memory request"
			},
		]
		enforcement: action: "deny"
	}
}

// Literal comparison — comparing a field against a fixed value
literalComparePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "compare-literal"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Compares input fields against literal values using various operators"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "CMP-103"
				description: "Deployment name must not equal 'default'"
				severity:    "medium"
				expr: compare: {
					left: {path: "metadata.name"}
					op: "!="
					right: {literal: "default"}
				}
				message: "deployment name must not be 'default'"
			},
			{
				id:          "CMP-104"
				description: "Image tag must match semver pattern"
				severity:    "high"
				expr: compare: {
					left: {path: "spec.image.tag"}
					op: "matches"
					right: {literal: "^v?[0-9]+\\.[0-9]+\\.[0-9]+$"}
				}
				message: "image tag must be a valid semantic version"
			},
		]
		enforcement: action: "deny"
	}
}

// Function-based comparison — using builtin functions in compare values
funcComparePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "compare-with-func"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Uses builtin functions within compare expressions"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "CMP-105"
				description: "Container count must not exceed 5"
				severity:    "medium"
				expr: compare: {
					left: {func: {
						name: "len"
						args: [{path: "spec.containers"}]
					}}
					op: "<="
					right: {literal: 5}
				}
				message: "must have at most 5 containers per pod"
			},
		]
		enforcement: action: "warn"
	}
}

// Cross-field comparison against a declared expectation.
//
// Note: comparing against a server environment variable is deliberately not
// supported. Policy authors are not necessarily server operators, and
// violation messages interpolate resolved values back to the caller, so
// reading the server's environment would be a secret-exfiltration path.
// Inject the expected value into the evaluation input instead — as an
// annotation here — so it travels with the request and is auditable.
envComparePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "compare-env"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Compares a deployment target against the cluster it was approved for"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "CMP-106"
				description: "Target cluster must match the approved cluster annotation"
				severity:    "high"
				expr: compare: {
					left: {path: "spec.targetCluster"}
					op: "=="
					right: {path: "metadata.annotations.\"garmr.io/approved-cluster\""}
				}
				message: "target cluster does not match the approved cluster annotation"
			},
		]
		enforcement: action: "deny"
	}
}
