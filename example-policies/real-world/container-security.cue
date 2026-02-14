// example-policies/real-world/container-security.cue
// Comprehensive Kubernetes container security policy
// Demonstrates combining multiple operators for real-world security enforcement
package realworld

containerSecurityPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "container-security"
		namespace: "security"
		labels: {
			compliance: "soc2"
			domain:     "kubernetes"
		}
	}
	spec: {
		description: "Enforces container security best practices for Kubernetes workloads"
		target: resources: [{kind: "Pod"}]
		rules: [
			{
				id:          "SEC-001"
				description: "Containers must not run as root"
				severity:    "critical"
				priority:    10
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: not: {
						match: {path: "c.securityContext.runAsRoot", equals: true}
					}
				}
				message:     "containers must not run as root"
				remediation: "Set securityContext.runAsRoot: false and specify a non-root runAsUser"
				category:    "security"
				tags: ["cis-benchmark", "pod-security"]
			},
			{
				id:          "SEC-002"
				description: "Containers must not use privileged mode"
				severity:    "critical"
				priority:    10
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: not: {
						match: {path: "c.securityContext.privileged", equals: true}
					}
				}
				message:     "containers must not run in privileged mode"
				remediation: "Set securityContext.privileged: false"
				category:    "security"
				tags: ["cis-benchmark", "pod-security"]
			},
			{
				id:          "SEC-003"
				description: "Container images must use specific tags, not latest"
				severity:    "high"
				priority:    20
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: not: {
						match: {path: "c.image", hasSuffix: ":latest"}
					}
				}
				message:     "container images must not use :latest tag"
				remediation: "Pin images to specific version tags (e.g., myapp:v1.2.3)"
				category:    "security"
				tags: ["supply-chain", "best-practice"]
			},
			{
				id:          "SEC-004"
				description: "Container images must come from approved registry"
				severity:    "critical"
				priority:    15
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: any: [
						{match: {path: "c.image", hasPrefix: "registry.example.com/"}},
						{match: {path: "c.image", hasPrefix: "gcr.io/my-project/"}},
					]
				}
				message:  "all container images must come from an approved registry"
				category: "security"
				tags: ["supply-chain"]
			},
			{
				id:          "SEC-005"
				description: "All containers must have resource limits"
				severity:    "high"
				priority:    30
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: all: [
						{match: {path: "c.resources.limits.cpu", exists: true}},
						{match: {path: "c.resources.limits.memory", exists: true}},
					]
				}
				message:     "every container must have CPU and memory limits"
				remediation: "Add resources.limits.cpu and resources.limits.memory to each container"
				category:    "resource-governance"
				tags: ["best-practice"]
			},
			{
				id:          "SEC-006"
				description: "Read-only root filesystem should be enabled"
				severity:    "medium"
				priority:    40
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					mode: "all"
					condition: match: {
						path:   "c.securityContext.readOnlyRootFilesystem"
						equals: true
					}
				}
				message:     "containers should use a read-only root filesystem"
				remediation: "Set securityContext.readOnlyRootFilesystem: true and use volume mounts for writable paths"
				category:    "security"
				tags: ["hardening"]
			},
		]
		enforcement: action: "deny"
		evaluation: {
			order:    "priority"
			failFast: false
		}
	}
}
