// examples/condition-operators/exists.cue
// Tests match.exists: true (present and non-null) and false (absent or null)
package operators

existsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "exists-operator"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates field existence using match.exists"
		target: resources: ["test-exists"]
		rules: [
			{
				id:          "EXISTS-001"
				description: "Required field must exist"
				severity:    "high"
				expr: match: {
					path:   "requiredField"
					exists: true
				}
				message: "requiredField is missing"
			},
			{
				id:          "EXISTS-002"
				description: "Nested field must exist"
				severity:    "medium"
				expr: match: {
					path:   "metadata.name"
					exists: true
				}
				message: "metadata.name is missing"
			},
		]
		enforcement: action: "deny"
	}
}

absentPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "absent-operator"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates field absence using match.exists: false"
		target: resources: ["test-absent"]
		rules: [
			{
				id:          "ABSENT-001"
				description: "Deprecated field must not exist"
				severity:    "medium"
				expr: match: {
					path:   "deprecatedField"
					exists: false
				}
				message: "deprecatedField should be removed"
			},
			{
				id:          "ABSENT-002"
				description: "Legacy config must not exist"
				severity:    "low"
				expr: match: {
					path:   "config.legacy"
					exists: false
				}
				message: "config.legacy should be migrated"
			},
		]
		enforcement: action: "warn"
	}
}
