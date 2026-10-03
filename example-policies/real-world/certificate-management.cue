// example-policies/real-world/certificate-management.cue
// TLS certificate lifecycle management policies
// Demonstrates datetime operators for certificate expiry and validity checks
package realworld

certificateManagementPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "certificate-management"
		namespace: "security"
		labels: {
			compliance: "pci-dss"
			domain:     "tls"
		}
	}
	spec: {
		description: "Validates TLS certificate configuration, expiry, and compliance"
		target: resources: [{kind: "Certificate"}]
		rules: [
			{
				id:          "CERT-001"
				description: "Certificate must not be expired"
				severity:    "critical"
				priority:    10
				expr: match: {
					path: "spec.notAfter"
					datetime: notExpired: true
				}
				message:     "certificate has expired — immediate renewal required"
				remediation: "Renew the certificate immediately and deploy the updated certificate"
				category:    "security"
				tags: ["tls", "certificate", "urgent"]
			},
			{
				id:          "CERT-002"
				description: "Certificate must have at least 30 days remaining"
				severity:    "high"
				priority:    20
				expr: match: {
					path: "spec.notAfter"
					datetime: expiresAfterDays: 30
				}
				message:     "certificate expires within 30 days — schedule renewal"
				remediation: "Schedule certificate renewal. Use automated cert-manager if available."
				url:         "https://cert-manager.io/docs/"
				category:    "security"
				tags: ["tls", "certificate"]
			},
			{
				id:          "CERT-003"
				description: "Certificate key size must be at least 2048 bits"
				severity:    "critical"
				priority:    15
				expr: match: {
					path:               "spec.keySize"
					greaterThanOrEqual: 2048
				}
				message:     "certificate key size must be >= 2048 bits"
				remediation: "Generate a new certificate with at least 2048-bit key size (4096 recommended)"
				category:    "security"
				tags: ["tls", "cryptography"]
			},
			{
				id:          "CERT-004"
				description: "Certificate must use approved signature algorithm"
				severity:    "high"
				priority:    15
				expr: match: {
					path: "spec.signatureAlgorithm"
					in: ["SHA256WithRSA", "SHA384WithRSA", "SHA512WithRSA", "ECDSAWithSHA256", "ECDSAWithSHA384"]
				}
				message:     "certificate must use an approved signature algorithm"
				remediation: "Use SHA256WithRSA or stronger"
				category:    "security"
				tags: ["tls", "cryptography"]
			},
			{
				id:          "CERT-005"
				description: "Certificate must include Subject Alternative Names"
				severity:    "medium"
				priority:    30
				expr: match: {
					path: "spec.subjectAlternativeNames"
					length: greaterThan: 0
				}
				message:     "certificate must include at least one Subject Alternative Name (SAN)"
				remediation: "Add the service hostname(s) as SANs to the certificate"
				category:    "compliance"
				tags: ["tls", "pci-dss"]
			},
			{
				id:          "CERT-006"
				description: "Wildcard certificates are discouraged in production"
				severity:    "medium"
				priority:    35
				expr: not: {
					match: {
						path:      "spec.commonName"
						hasPrefix: "*."
					}
				}
				message:     "wildcard certificates are discouraged in production"
				remediation: "Use specific domain certificates instead of wildcards"
				category:    "security"
				tags: ["tls", "best-practice"]
			},
		]
		enforcement: action: "deny"
		evaluation: {
			order:    "priority"
			failFast: false
		}
	}
}
