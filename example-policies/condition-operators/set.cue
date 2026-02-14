// example-policies/condition-operators/set.cue
// Demonstrates set membership operators: in and notIn
package operators

allowedValuesPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "set-membership"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates set membership using in and notIn operators"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "SET-001"
				description: "Environment must be a recognized DTAP value"
				severity:    "high"
				expr: match: {
					path: "environment"
					in: ["development", "staging", "production"]
				}
				message:     "environment must be one of: development, staging, production"
				remediation: "Set environment to a valid DTAP value"
				category:    "compliance"
			},
			{
				id:          "SET-002"
				description: "Region must be in approved list"
				severity:    "medium"
				expr: match: {
					path: "region"
					in: ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"]
				}
				message:  "region must be one of the approved cloud regions"
				category: "compliance"
			},
			{
				id:          "SET-003"
				description: "Image registry must not use untrusted public sources"
				severity:    "critical"
				expr: match: {
					path: "spec.image.registry"
					notIn: ["docker.io", "quay.io", "public.ecr.aws"]
				}
				message:     "image registry must not be a public registry"
				remediation: "Use your organization's private container registry"
				category:    "security"
				tags: ["container", "supply-chain"]
			},
		]
		enforcement: action: "deny"
	}
}
