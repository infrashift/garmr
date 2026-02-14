// examples/condition-operators/exists.cue
// Tests the exists and absent operators
package operators

existsPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "exists-operator"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates field existence using exists and absent operators"
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
		description: "Validates field absence using absent operator"
		target: resources: ["test-absent"]
		rules: [
			{
				id:          "ABSENT-001"
				description: "Deprecated field must not exist"
				severity:    "medium"
				expr: match: {
					path:   "deprecatedField"
					absent: true
				}
				message: "deprecatedField should be removed"
			},
			{
				id:          "ABSENT-002"
				description: "Legacy config must not exist"
				severity:    "low"
				expr: match: {
					path:   "config.legacy"
					absent: true
				}
				message: "config.legacy should be migrated"
			},
		]
		enforcement: action: "warn"
	}
}