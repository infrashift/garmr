// example-policies/condition-operators/set.cue
// Demonstrates set operators: in, notIn, unique, uniqueBy, sorted,
// containsAll, and subsetOf
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

// Advanced set validation on array fields: uniqueness, ordering, and
// superset/subset checks.
advancedSetPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "set-advanced"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates arrays with unique, uniqueBy, sorted, containsAll, and subsetOf"
		target: resources: [{kind: "test-set-advanced"}]
		rules: [
			{
				id:          "SET-101"
				description: "Service ports must not contain duplicates"
				severity:    "high"
				expr: match: {
					path:   "spec.ports"
					unique: true
				}
				message:  "service ports must be unique"
				category: "quality"
			},
			{
				id:          "SET-102"
				description: "Container names must be unique within the pod"
				severity:    "high"
				expr: match: {
					path:     "spec.containers"
					uniqueBy: "name"
				}
				message:  "container names must be unique"
				category: "quality"
			},
			{
				id:          "SET-103"
				description: "Priorities must be in ascending order"
				severity:    "medium"
				expr: match: {
					path:   "spec.priorities"
					sorted: "asc"
				}
				message:  "priorities must be sorted in ascending order"
				category: "quality"
			},
			{
				id:          "SET-104"
				description: "Deployment must cover all DR-required regions"
				severity:    "critical"
				expr: match: {
					path: "spec.regions"
					containsAll: ["us-east-1", "eu-west-1"]
				}
				message:     "deployment must include all required DR regions"
				remediation: "Add the missing regions to spec.regions"
				category:    "compliance"
			},
			{
				id:          "SET-105"
				description: "Zones must be from the approved list"
				severity:    "high"
				expr: match: {
					path: "spec.zones"
					subsetOf: ["zone-a", "zone-b", "zone-c", "zone-d"]
				}
				message:  "zones must be selected from the approved zone list"
				category: "compliance"
			},
		]
		enforcement: action: "deny"
	}
}
