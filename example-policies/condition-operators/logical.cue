// example-policies/condition-operators/logical.cue
// Demonstrates logical combinators: all (AND), any (OR), not (negation)
// These operators compose expressions into complex conditions
package operators

// All combinator (AND) — every condition must pass
allCombinatorPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "logical-all"
		namespace: "condition-operators"
	}
	spec: {
		description: "Demonstrates the 'all' (AND) combinator — every condition must pass"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "LOG-001"
				description: "Production services must have HA and resource limits"
				severity:    "high"
				expr: all: [
					{match: {path: "environment", equals: "production"}},
					{match: {path: "spec.replicas", greaterThanOrEqual: 2}},
					{match: {path: "spec.resources.cpuLimit", greaterThan: 0}},
					{match: {path: "spec.resources.memoryLimit", greaterThan: 0}},
				]
				message:     "production services must have >= 2 replicas and resource limits set"
				remediation: "Set replicas >= 2, and configure CPU and memory limits"
				category:    "production-readiness"
			},
		]
		enforcement: action: "deny"
	}
}

// Any combinator (OR) — at least one condition must pass
anyCombinatorPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "logical-any"
		namespace: "condition-operators"
	}
	spec: {
		description: "Demonstrates the 'any' (OR) combinator — at least one condition must pass"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "LOG-002"
				description: "Authentication must use at least one approved method"
				severity:    "critical"
				expr: any: [
					{match: {path: "spec.auth.method", equals: "oauth2"}},
					{match: {path: "spec.auth.method", equals: "oidc"}},
					{match: {path: "spec.auth.method", equals: "mtls"}},
				]
				message:     "auth method must be one of: oauth2, oidc, mtls"
				remediation: "Configure an approved authentication method"
				category:    "security"
				tags: ["authentication", "compliance"]
			},
		]
		enforcement: action: "deny"
	}
}

// Not combinator (negation) — the inner condition must fail for the rule to pass
notCombinatorPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "logical-not"
		namespace: "condition-operators"
	}
	spec: {
		description: "Demonstrates the 'not' combinator — the inner expression must fail"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "LOG-003"
				description: "Debug mode must not be enabled"
				severity:    "high"
				expr: not: {
					match: {
						path:   "spec.debug"
						equals: true
					}
				}
				message:     "debug mode must not be enabled in production"
				remediation: "Set spec.debug to false"
				category:    "security"
			},
		]
		enforcement: action: "deny"
	}
}

// Nested combination — all + any + not composed together
nestedLogicPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "logical-nested"
		namespace: "condition-operators"
	}
	spec: {
		description: "Demonstrates nested logical operators: all containing any and not"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "LOG-004"
				description: "Deployment must meet minimum security requirements"
				severity:    "critical"
				expr: all: [
					// Must have TLS enabled
					{match: {path: "spec.tls.enabled", equals: true}},
					// Must use approved protocol
					{any: [
						{match: {path: "spec.protocol", equals: "https"}},
						{match: {path: "spec.protocol", equals: "grpcs"}},
					]},
					// Must not run as root
					{not: {match: {path: "spec.runAsRoot", equals: true}}},
				]
				message:     "deployment must have TLS, use HTTPS/gRPCS, and not run as root"
				remediation: "Enable TLS, use a secure protocol, and disable root execution"
				category:    "security"
				tags: ["hardening", "compliance"]
			},
		]
		enforcement: action: "deny"
	}
}
