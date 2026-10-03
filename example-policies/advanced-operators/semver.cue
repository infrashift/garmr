// example-policies/advanced-operators/semver.cue
// Demonstrates semantic version comparison using the semver operator
// Supports: equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual
package advanced

semverPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "semver-constraints"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Validates semantic versioning constraints on application versions"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "SV-001"
				description: "Application version must be >= 2.0.0"
				severity:    "high"
				expr: match: {
					path: "spec.version"
					semver: greaterThanOrEqual: "2.0.0"
				}
				message:     "application version must be >= 2.0.0"
				remediation: "Upgrade to version 2.0.0 or later"
				category:    "compatibility"
			},
			{
				id:          "SV-002"
				description: "Application version must be < 4.0.0 (unsupported)"
				severity:    "medium"
				expr: match: {
					path: "spec.version"
					semver: lessThan: "4.0.0"
				}
				message:  "version 4.x is not yet supported"
				category: "compatibility"
			},
			{
				id:          "SV-003"
				description: "Database driver must be exact version 1.5.2"
				severity:    "critical"
				expr: match: {
					path: "spec.dependencies.dbDriver"
					semver: equals: "1.5.2"
				}
				message:     "database driver must be exactly version 1.5.2 (known stable)"
				remediation: "Pin database driver to v1.5.2"
				category:    "stability"
			},
		]
		enforcement: action: "deny"
	}
}
