// example-policies/advanced-operators/foreach.cue
// Demonstrates the forEach expression for iterating over collections
// forEach evaluates a condition for each element in an array field
package advanced

// ForEach with mode "all" — every element must satisfy the condition
forEachAllPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "foreach-all"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Iterates over containers — every container must pass all checks"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FE-001"
				description: "All containers must have resource limits"
				severity:    "high"
				expr: forEach: {
					path: "spec.containers"
					as:   "container"
					mode: "all"
					condition: all: [
						{match: {path: "container.resources.cpuLimit", exists: true}},
						{match: {path: "container.resources.memoryLimit", exists: true}},
					]
				}
				message:     "every container must have CPU and memory limits set"
				remediation: "Add resources.cpuLimit and resources.memoryLimit to each container"
				category:    "resource-governance"
			},
			{
				id:          "FE-002"
				description: "All containers must use approved image registry"
				severity:    "critical"
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: match: {
						path:      "c.image"
						hasPrefix: "registry.example.com/"
					}
				}
				message:  "all container images must come from registry.example.com"
				category: "security"
				tags: ["supply-chain"]
			},
		]
		enforcement: action: "deny"
	}
}

// ForEach with mode "any" — at least one element must satisfy the condition
forEachAnyPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "foreach-any"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Iterates over a collection — at least one element must match"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FE-003"
				description: "At least one maintainer must have admin role"
				severity:    "medium"
				expr: forEach: {
					path: "spec.maintainers"
					as:   "maintainer"
					mode: "any"
					condition: match: {
						path:   "maintainer.role"
						equals: "admin"
					}
				}
				message: "at least one maintainer must have the 'admin' role"
			},
		]
		enforcement: action: "warn"
	}
}

// ForEach with nested logic — complex per-element validation
forEachNestedPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "foreach-nested"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Complex per-element checks combining forEach with logical operators"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "FE-004"
				description: "All ports must be named and within valid range"
				severity:    "high"
				expr: forEach: {
					path: "spec.ports"
					as:   "port"
					mode: "all"
					condition: all: [
						{match: {path: "port.name", exists: true}},
						{match: {path: "port.number", greaterThan: 0}},
						{match: {path: "port.number", lessThanOrEqual: 65535}},
						{not: {match: {path: "port.number", in: [22, 23, 3389]}}},
					]
				}
				message:     "all ports must be named, in range 1-65535, and not use restricted ports (22, 23, 3389)"
				remediation: "Name each port and ensure it is not a restricted management port"
				category:    "networking"
				tags: ["security", "best-practice"]
			},
		]
		enforcement: action: "deny"
	}
}
