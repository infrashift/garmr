// example-policies/condition-operators/string.cue
// Demonstrates string matching operators: contains, hasPrefix, hasSuffix, pattern
package operators

stringMatchPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "string-matching"
		namespace: "condition-operators"
	}
	spec: {
		description: "Validates string fields using substring and regex operators"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "STR-001"
				description: "Image tag must not contain 'latest'"
				severity:    "high"
				expr: not: {
					match: {
						path:     "spec.image.tag"
						contains: "latest"
					}
				}
				message:     "image tag must not contain 'latest' — use a specific version"
				remediation: "Pin your image to a specific semantic version tag"
				category:    "security"
				tags: ["container", "best-practice"]
			},
			{
				id:          "STR-002"
				description: "Service name must start with team prefix"
				severity:    "medium"
				expr: match: {
					path:      "metadata.name"
					hasPrefix: "team-"
				}
				message:  "service name must start with 'team-' prefix"
				category: "naming"
			},
			{
				id:          "STR-003"
				description: "Hostname must end with approved domain"
				severity:    "high"
				expr: match: {
					path:      "spec.ingress.hostname"
					hasSuffix: ".example.com"
				}
				message:  "hostname must end with '.example.com'"
				category: "networking"
			},
			{
				id:          "STR-004"
				description: "Version label must follow semver format"
				severity:    "medium"
				expr: match: {
					path:    "metadata.labels.version"
					pattern: "^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9.]+)?$"
				}
				message:     "version label must match semver pattern (e.g., v1.2.3 or 1.2.3-rc.1)"
				remediation: "Use semantic versioning: https://semver.org"
				category:    "compliance"
			},
		]
		enforcement: action: "deny"
	}
}
