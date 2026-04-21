// example-policies/real-world/resource-governance.cue
// Cloud resource governance policies for cost control and operational standards
// Demonstrates combining match, compare, and logical operators
package realworld

resourceGovernancePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "cloud-resource-governance"
		namespace: "cloud-governance"
		labels: {
			domain: "cloud"
			team:   "platform"
		}
	}
	spec: {
		description: "Enforces resource governance standards for cost control and operational excellence"
		target: resources: [{kind: "CloudResource"}]
		rules: [
			{
				id:          "GOV-001"
				description: "All resources must have an owner label"
				severity:    "high"
				expr: match: {
					path:   "metadata.labels.owner"
					exists: true
				}
				message:     "all resources must have a metadata.labels.owner"
				remediation: "Add an 'owner' label with your team name"
				category:    "governance"
				tags: ["tagging", "accountability"]
			},
			{
				id:          "GOV-002"
				description: "All resources must have a cost-center label"
				severity:    "medium"
				expr: match: {
					path:   "metadata.labels.costCenter"
					exists: true
				}
				message:  "all resources must have a metadata.labels.costCenter"
				category: "governance"
				tags: ["tagging", "finops"]
			},
			{
				id:          "GOV-003"
				description: "Instance type must be from approved list"
				severity:    "high"
				expr: match: {
					path: "spec.instanceType"
					in: [
						"t3.micro", "t3.small", "t3.medium", "t3.large",
						"m5.large", "m5.xlarge", "m5.2xlarge",
						"c5.large", "c5.xlarge", "c5.2xlarge",
					]
				}
				message:     "instance type must be from the approved list"
				remediation: "Choose an approved instance type from the platform catalog"
				category:    "cost"
				tags: ["finops", "compute"]
			},
			{
				id:          "GOV-004"
				description: "Auto-scaling must have reasonable bounds"
				severity:    "medium"
				expr: all: [
					{match: {path: "spec.autoscaling.minReplicas", greaterThanOrEqual: 1}},
					{match: {path: "spec.autoscaling.maxReplicas", lessThanOrEqual: 50}},
					{compare: {
						left:  {path: "spec.autoscaling.maxReplicas"}
						op:    ">"
						right: {path: "spec.autoscaling.minReplicas"}
					}},
				]
				message:     "autoscaling: min >= 1, max <= 50, and max > min"
				remediation: "Set reasonable autoscaling bounds"
				category:    "cost"
				tags: ["autoscaling", "finops"]
			},
			{
				id:          "GOV-005"
				description: "Storage volumes must not exceed 500 GB"
				severity:    "medium"
				expr: match: {
					path:            "spec.storage.sizeGB"
					lessThanOrEqual: 500
				}
				message:     "storage volume must not exceed 500 GB"
				remediation: "Request a storage exception or reduce volume size"
				category:    "cost"
				tags: ["storage", "finops"]
			},
			{
				id:          "GOV-006"
				description: "Resources must have a valid environment tag"
				severity:    "high"
				expr: match: {
					path: "metadata.labels.environment"
					in: ["development", "staging", "production"]
				}
				message:  "resources must be tagged with a valid environment"
				category: "governance"
				tags: ["tagging"]
			},
		]
		enforcement: action: "deny"
	}
}
