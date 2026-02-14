// example-policies/builtins/func-calls.cue
// Demonstrates the func expression for calling builtin functions
// Builtins can validate, transform, and inspect input data
package builtins

// CIDR network validation — check if an IP is within a network range
cidrValidationPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "builtin-cidr"
		namespace: "builtins"
	}
	spec: {
		description: "Uses cidrContains and ipVersion builtins for network validation"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FN-001"
				description: "Pod IP must be within cluster CIDR"
				severity:    "critical"
				expr: "func": {
					name:   "cidrContains"
					args: ["10.244.0.0/16", "input.spec.podIP"]
					expect: true
				}
				message:  "pod IP must be within 10.244.0.0/16 cluster CIDR"
				category: "networking"
				tags: ["cidr", "network-policy"]
			},
			{
				id:          "FN-002"
				description: "Service IP must be IPv4"
				severity:    "high"
				expr: "func": {
					name:   "ipVersion"
					args: ["input.spec.serviceIP"]
					expect: 4
				}
				message:  "service IP must be IPv4"
				category: "networking"
			},
		]
		enforcement: action: "deny"
	}
}

// Kubernetes resource unit parsing — validate resource quantities
k8sUnitsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "builtin-k8s-units"
		namespace: "builtins"
	}
	spec: {
		description: "Uses unitsParse to validate Kubernetes resource quantities"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FN-003"
				description: "CPU request must be at least 100m (0.1 cores)"
				severity:    "medium"
				expr: compare: {
					left: {func: {
						name: "unitsParse"
						args: [{path: "spec.resources.requests.cpu"}]
					}}
					op:    ">="
					right: {func: {
						name: "unitsParse"
						args: [{literal: "100m"}]
					}}
				}
				message:     "CPU request must be at least 100m"
				remediation: "Set spec.resources.requests.cpu to 100m or higher"
				category:    "resource-governance"
			},
		]
		enforcement: action: "warn"
	}
}

// Type checking — validate field types at runtime
typeCheckPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "builtin-type-check"
		namespace: "builtins"
	}
	spec: {
		description: "Uses typeOf and isType builtins to validate field types"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FN-004"
				description: "Replicas must be a number"
				severity:    "high"
				expr: "func": {
					name:   "isType"
					args: ["input.spec.replicas", "number"]
					expect: true
				}
				message: "spec.replicas must be a number, not a string"
			},
			{
				id:          "FN-005"
				description: "Labels must be a map"
				severity:    "medium"
				expr: "func": {
					name:   "isType"
					args: ["input.metadata.labels", "map"]
					expect: true
				}
				message: "metadata.labels must be an object/map"
			},
		]
		enforcement: action: "deny"
	}
}

// String and encoding builtins — base64, lower/upper, split
encodingPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "builtin-encoding"
		namespace: "builtins"
	}
	spec: {
		description: "Uses encoding and string builtins for data validation"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FN-006"
				description: "Secret data must be valid base64"
				severity:    "high"
				expr: "func": {
					name: "base64Decode"
					args: ["input.spec.secretData"]
					bind: "decodedSecret"
				}
				message: "spec.secretData must be valid base64-encoded data"
			},
			{
				id:          "FN-007"
				description: "Namespace must be lowercase"
				severity:    "medium"
				expr: "func": {
					name:   "lower"
					args: ["input.metadata.namespace"]
					expect: "input.metadata.namespace"
				}
				message: "metadata.namespace must be all lowercase"
			},
		]
		enforcement: action: "deny"
	}
}

// Map and lookup builtins — hasKey, lookup, keys
mapOperationsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "builtin-map-ops"
		namespace: "builtins"
	}
	spec: {
		description: "Uses map-related builtins for structured data validation"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FN-008"
				description: "Annotations must contain the 'managed-by' key"
				severity:    "medium"
				expr: "func": {
					name:   "hasKey"
					args: ["input.metadata.annotations", "managed-by"]
					expect: true
				}
				message:     "metadata.annotations must include the 'managed-by' key"
				remediation: "Add 'managed-by: <tool>' to your resource annotations"
				category:    "governance"
			},
		]
		enforcement: action: "warn"
	}
}
