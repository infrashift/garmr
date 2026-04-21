// example-policies/real-world/cloud-resource-governance-terraform.cue
// Cloud resource governance applied directly to Terraform plan JSON
// (the shape produced by `terraform show -json`).
//
// Each rule iterates over `resource_changes[]` with forEach and inspects
// `change.after.*`. Rules scoped to a specific provider resource type
// (instance type, autoscaling bounds, volume size) skip resources of
// other types via a per-item type guard.
//
// Every rule is additionally guarded with `any: [{absent: "resource_changes"}, forEach]`
// so the policy passes vacuously when evaluated against non-Terraform input.
package realworld

cloudResourceGovernanceTerraformPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "cloud-resource-governance-terraform"
		namespace: "cloud-governance"
		labels: {
			domain: "cloud"
			team:   "platform"
			format: "terraform-plan"
		}
	}
	spec: {
		description: "Enforces governance standards on Terraform plan JSON (terraform show -json)"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "TF-001"
				description: "Every resource must be tagged with an Owner"
				severity:    "high"
				expr: any: [
					{absent: "resource_changes"},
					{forEach: {
						path: "resource_changes"
						as:   "r"
						mode: "all"
						condition: match: {
							path:   "r.change.after.tags.Owner"
							exists: true
						}
					}},
				]
				message:     "every resource_change must have tags.Owner set"
				remediation: "Add an Owner tag to the resource's `tags` block"
				category:    "governance"
				tags: ["tagging", "accountability"]
			},
			{
				id:          "TF-002"
				description: "Every resource must be tagged with a CostCenter"
				severity:    "medium"
				expr: any: [
					{absent: "resource_changes"},
					{forEach: {
						path: "resource_changes"
						as:   "r"
						mode: "all"
						condition: match: {
							path:   "r.change.after.tags.CostCenter"
							exists: true
						}
					}},
				]
				message:  "every resource_change must have tags.CostCenter set"
				category: "governance"
				tags: ["tagging", "finops"]
			},
			{
				id:          "TF-003"
				description: "aws_instance instance_type must be from approved list"
				severity:    "high"
				expr: any: [
					{absent: "resource_changes"},
					{forEach: {
						path: "resource_changes"
						as:   "r"
						mode: "all"
						condition: any: [
							{not: {match: {path: "r.type", equals: "aws_instance"}}},
							{match: {
								path: "r.change.after.instance_type"
								in: [
									"t3.micro", "t3.small", "t3.medium", "t3.large",
									"m5.large", "m5.xlarge", "m5.2xlarge",
									"c5.large", "c5.xlarge", "c5.2xlarge",
								]
							}},
						]
					}},
				]
				message:     "aws_instance.instance_type must be from the approved catalog"
				remediation: "Choose an approved instance type from the platform catalog"
				category:    "cost"
				tags: ["finops", "compute"]
			},
			{
				id:          "TF-004"
				description: "aws_autoscaling_group must have reasonable bounds"
				severity:    "medium"
				expr: any: [
					{absent: "resource_changes"},
					{forEach: {
						path: "resource_changes"
						as:   "r"
						mode: "all"
						condition: any: [
							{not: {match: {path: "r.type", equals: "aws_autoscaling_group"}}},
							{all: [
								{match: {path: "r.change.after.min_size", greaterThanOrEqual: 1}},
								{match: {path: "r.change.after.max_size", lessThanOrEqual: 50}},
								{compare: {
									left:  {path: "r.change.after.max_size"}
									op:    ">"
									right: {path: "r.change.after.min_size"}
								}},
							]},
						]
					}},
				]
				message:     "aws_autoscaling_group: min_size >= 1, max_size <= 50, and max > min"
				remediation: "Set reasonable autoscaling bounds on the autoscaling group"
				category:    "cost"
				tags: ["autoscaling", "finops"]
			},
			{
				id:          "TF-005"
				description: "aws_ebs_volume size must not exceed 500 GB"
				severity:    "medium"
				expr: any: [
					{absent: "resource_changes"},
					{forEach: {
						path: "resource_changes"
						as:   "r"
						mode: "all"
						condition: any: [
							{not: {match: {path: "r.type", equals: "aws_ebs_volume"}}},
							{match: {path: "r.change.after.size", lessThanOrEqual: 500}},
						]
					}},
				]
				message:     "aws_ebs_volume.size must be <= 500 GB"
				remediation: "Request an exception or reduce the volume size"
				category:    "cost"
				tags: ["storage", "finops"]
			},
			{
				id:          "TF-006"
				description: "Every resource must be tagged with a valid Environment"
				severity:    "high"
				expr: any: [
					{absent: "resource_changes"},
					{forEach: {
						path: "resource_changes"
						as:   "r"
						mode: "all"
						condition: match: {
							path: "r.change.after.tags.Environment"
							in: ["development", "staging", "production"]
						}
					}},
				]
				message:  "every resource_change must have tags.Environment in {development, staging, production}"
				category: "governance"
				tags: ["tagging"]
			},
		]
		enforcement: action: "deny"
	}
}
