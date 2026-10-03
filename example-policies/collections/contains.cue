// example-policies/collections/contains.cue
// Demonstrates collection membership checks with match.containsAll and
// match.containsAny
package collections

// containsAll with one value — the collection includes a specific item
containsValuePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "contains-value"
		namespace: "collections"
	}
	spec: {
		description: "Checks if a collection contains a specific value"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "COL-001"
				description: "Approved reviewers list must include the security team"
				severity:    "high"
				expr: match: {
					path: "spec.reviewers"
					containsAll: ["security-team"]
				}
				message:     "the security team must be included in the reviewers list"
				remediation: "Add 'security-team' to spec.reviewers"
				category:    "compliance"
			},
			{
				id:          "COL-002"
				description: "Supported protocols must include HTTPS"
				severity:    "critical"
				expr: match: {
					path: "spec.protocols"
					containsAll: ["https"]
				}
				message:  "HTTPS must be in the list of supported protocols"
				category: "security"
			},
		]
		enforcement: action: "deny"
	}
}

// containsAll — every listed value must be present in the collection
containsAllPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "contains-all"
		namespace: "collections"
	}
	spec: {
		description: "Checks that a collection contains ALL of the required values"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "COL-003"
				description: "Required labels must all be present"
				severity:    "high"
				expr: match: {
					path: "metadata.requiredLabels"
					containsAll: ["environment", "owner", "cost-center"]
				}
				message:     "must have all required labels: environment, owner, cost-center"
				remediation: "Add all mandatory labels to the resource"
				category:    "governance"
				tags: ["tagging", "compliance"]
			},
			{
				id:          "COL-004"
				description: "Monitoring endpoints must include health and metrics"
				severity:    "medium"
				expr: match: {
					path: "spec.monitoring.endpoints"
					containsAll: ["/healthz", "/metrics"]
				}
				message:  "monitoring must expose both /healthz and /metrics endpoints"
				category: "observability"
			},
		]
		enforcement: action: "deny"
	}
}

// containsAny — at least one of the listed values must be present
containsAnyPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "contains-any"
		namespace: "collections"
	}
	spec: {
		description: "Checks that a collection contains at least one of the specified values"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "COL-005"
				description: "At least one approved logging format must be configured"
				severity:    "medium"
				expr: match: {
					path: "spec.logging.formats"
					containsAny: ["json", "structured"]
				}
				message:     "at least one structured logging format must be configured"
				remediation: "Add 'json' or 'structured' to spec.logging.formats"
				category:    "observability"
			},
			{
				id:          "COL-006"
				description: "Deployment must target at least one approved availability zone"
				severity:    "high"
				expr: match: {
					path: "spec.availabilityZones"
					containsAny: ["us-east-1a", "us-east-1b", "us-east-1c", "eu-west-1a", "eu-west-1b"]
				}
				message:  "must target at least one approved availability zone"
				category: "compliance"
				tags: ["infrastructure"]
			},
		]
		enforcement: action: "deny"
	}
}
