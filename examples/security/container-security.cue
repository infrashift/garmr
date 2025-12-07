// examples/security/container-security.cue
// Container Security Policy
// Enforces security requirements for container deployments
package security

// Container security policy
containerSecurity: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "container-security"
        namespace: "security"
        labels: {
            "category": "security"
            "framework": "cis-benchmark"
        }
    }
    spec: {
        description: "Container security requirements based on CIS benchmarks"
        target: {
            resources: ["container", "pod", "deployment"]
        }
        rules: [
            // No privileged containers
            {
                id: "SEC-001"
                description: "Containers must not run as privileged"
                severity: "critical"
                category: "security"
                tags: ["cis", "privileged"]
                expr: {
                    any: [
                        {match: {path: "spec.privileged", exists: false}},
                        {match: {path: "spec.privileged", equals: false}}
                    ]
                }
                message: "Container is running in privileged mode"
                remediation: "Set spec.privileged to false"
            },
            // Must not run as root
            {
                id: "SEC-002"
                description: "Containers must not run as root"
                severity: "high"
                category: "security"
                tags: ["cis", "root"]
                expr: {
                    any: [
                        {match: {path: "spec.runAsNonRoot", equals: true}},
                        {match: {path: "spec.runAsUser", greaterThan: 0}}
                    ]
                }
                message: "Container may be running as root"
                remediation: "Set spec.runAsNonRoot to true or specify a non-root user"
            },
            // Read-only root filesystem
            {
                id: "SEC-003"
                description: "Root filesystem should be read-only"
                severity: "medium"
                category: "security"
                tags: ["cis", "filesystem"]
                expr: {
                    match: {
                        path: "spec.readOnlyRootFilesystem"
                        equals: true
                    }
                }
                message: "Root filesystem is not read-only"
                remediation: "Set spec.readOnlyRootFilesystem to true"
            },
            // Resource limits must be set
            {
                id: "SEC-004"
                description: "Resource limits must be defined"
                severity: "medium"
                category: "resources"
                tags: ["limits"]
                expr: {
                    all: [
                        {match: {path: "spec.resources.limits.memory", exists: true}},
                        {match: {path: "spec.resources.limits.cpu", exists: true}}
                    ]
                }
                message: "Resource limits are not defined"
                remediation: "Set spec.resources.limits.memory and spec.resources.limits.cpu"
            },
            // Image must be from allowed registries
            {
                id: "SEC-005"
                description: "Container image must be from allowed registry"
                severity: "high"
                category: "supply-chain"
                tags: ["registry", "supply-chain"]
                expr: {
                    any: [
                        {match: {path: "spec.image", hasPrefix: "gcr.io/"}},
                        {match: {path: "spec.image", hasPrefix: "docker.io/library/"}},
                        {match: {path: "spec.image", hasPrefix: "ghcr.io/"}}
                    ]
                }
                message: "Container image is not from an allowed registry"
                remediation: "Use images from gcr.io, docker.io/library, or ghcr.io"
            },
            // No latest tag
            {
                id: "SEC-006"
                description: "Container image must not use 'latest' tag"
                severity: "medium"
                category: "supply-chain"
                tags: ["tag", "versioning"]
                expr: {
                    not: {
                        match: {
                            path: "spec.image"
                            hasSuffix: ":latest"
                        }
                    }
                }
                message: "Container image uses 'latest' tag"
                remediation: "Use a specific version tag instead of 'latest'"
            }
        ]
        enforcement: {
            action: "deny"
        }
    }
}

// Network security policy
networkSecurity: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "network-security"
        namespace: "security"
        labels: {
            "category": "security"
            "framework": "network"
        }
    }
    spec: {
        description: "Network security requirements"
        target: {
            resources: ["service", "ingress", "networkpolicy"]
        }
        rules: [
            // HTTPS required for external traffic
            {
                id: "NET-001"
                description: "External services must use HTTPS"
                severity: "high"
                category: "network"
                expr: {
                    any: [
                        {match: {path: "spec.tls.enabled", equals: true}},
                        {match: {path: "spec.protocol", equals: "HTTPS"}},
                        {match: {path: "spec.internal", equals: true}}
                    ]
                }
                message: "External service is not using HTTPS"
            },
            // Port range restrictions
            {
                id: "NET-002"
                description: "Service ports must be in allowed range"
                severity: "medium"
                category: "network"
                expr: {
                    all: [
                        {match: {path: "spec.port", greaterThanOrEqual: 1024}},
                        {match: {path: "spec.port", lessThanOrEqual: 65535}}
                    ]
                }
                message: "Service port is not in allowed range (1024-65535)"
            }
        ]
        enforcement: {
            action: "warn"
        }
    }
}