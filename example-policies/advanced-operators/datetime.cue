// example-policies/advanced-operators/datetime.cue
// Demonstrates datetime constraints for time-based policy decisions
// Supports: notExpired, expiresAfterDays, withinDays, withinHours, after, before
package advanced

datetimePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "datetime-constraints"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Validates datetime fields for expiry, freshness, and time-window compliance"
		target: resources: [{kind: "*"}]
		rules: [
			{
				id:          "DT-001"
				description: "Certificate must not be expired"
				severity:    "critical"
				expr: match: {
					path: "spec.certificate.notAfter"
					datetime: notExpired: true
				}
				message:     "certificate has expired"
				remediation: "Renew the certificate before expiration"
				category:    "security"
				tags: ["tls", "certificate"]
			},
			{
				id:          "DT-002"
				description: "Certificate must have at least 30 days until expiry"
				severity:    "high"
				expr: match: {
					path: "spec.certificate.notAfter"
					datetime: expiresAfterDays: 30
				}
				message:     "certificate expires within 30 days — renew soon"
				remediation: "Rotate certificates with at least 30 days remaining"
				category:    "security"
				tags: ["tls", "certificate"]
			},
			{
				id:          "DT-003"
				description: "Last security scan must be within 7 days"
				severity:    "high"
				expr: match: {
					path: "spec.lastSecurityScan"
					datetime: withinDays: 7
				}
				message:     "last security scan is older than 7 days"
				remediation: "Run a security scan and update spec.lastSecurityScan"
				category:    "security"
				tags: ["scanning", "compliance"]
			},
			{
				id:          "DT-004"
				description: "Build timestamp must be within 24 hours"
				severity:    "medium"
				expr: match: {
					path: "spec.buildTimestamp"
					datetime: withinHours: 24
				}
				message:  "build is older than 24 hours — rebuild for freshness"
				category: "quality"
			},
		]
		enforcement: action: "deny"
	}
}
