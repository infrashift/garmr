// examples/advanced/advanced-policies.cue
// Advanced policy examples demonstrating forEach, length, semver, datetime, and field reference
package advanced

// Kubernetes container security with forEach (iterate all containers)
k8sContainerPolicy: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "k8s-container-policy"
        namespace: "advanced"
    }
    spec: {
        description: "Kubernetes container security - validates all containers in a pod"
        target: resources: ["pod", "deployment"]
        rules: [
            {
                id: "K8S-001"
                description: "All containers must have resource limits"
                severity: "high"
                expr: {
                    forEach: {
                        path: "spec.containers"
                        as: "container"
                        condition: {
                            all: [
                                {match: {path: "container.resources.limits.memory", exists: true}},
                                {match: {path: "container.resources.limits.cpu", exists: true}}
                            ]
                        }
                    }
                }
                message: "One or more containers missing resource limits"
            },
            {
                id: "K8S-002"
                description: "All containers must use allowed registries"
                severity: "critical"
                expr: {
                    forEach: {
                        path: "spec.containers"
                        as: "container"
                        condition: {
                            any: [
                                {match: {path: "container.image", hasPrefix: "gcr.io/"}},
                                {match: {path: "container.image", hasPrefix: "docker.io/"}},
                                {match: {path: "container.image", hasPrefix: "ghcr.io/"}}
                            ]
                        }
                    }
                }
                message: "One or more containers use unauthorized image registries"
            },
            {
                id: "K8S-003"
                description: "No container may run as privileged"
                severity: "critical"
                expr: {
                    forEach: {
                        path: "spec.containers"
                        as: "container"
                        condition: {
                            any: [
                                {match: {path: "container.securityContext.privileged", exists: false}},
                                {match: {path: "container.securityContext.privileged", equals: false}}
                            ]
                        }
                    }
                }
                message: "One or more containers running in privileged mode"
            }
        ]
        enforcement: action: "deny"
    }
}

// Length validation policy
lengthPolicy: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "length-policy"
        namespace: "advanced"
    }
    spec: {
        description: "Validates lengths of arrays and strings"
        target: resources: ["deployment"]
        rules: [
            {
                id: "LEN-001"
                description: "Name must be between 3 and 63 characters"
                severity: "medium"
                expr: {
                    match: {
                        path: "metadata.name"
                        length: {min: 3, max: 63}
                    }
                }
                message: "Name must be between 3 and 63 characters"
            },
            {
                id: "LEN-002"
                description: "Must have at least 2 replicas"
                severity: "high"
                expr: {
                    match: {
                        path: "spec.replicas"
                        greaterThanOrEqual: 2
                    }
                }
                message: "At least 2 replicas required for high availability"
            },
            {
                id: "LEN-003"
                description: "Labels must not be empty"
                severity: "low"
                expr: {
                    match: {
                        path: "metadata.labels"
                        length: {greaterThan: 0}
                    }
                }
                message: "At least one label is required"
            }
        ]
        enforcement: action: "warn"
    }
}

// Semantic version policy
semverPolicy: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "semver-policy"
        namespace: "advanced"
    }
    spec: {
        description: "Validates semantic versions"
        target: resources: ["release", "deployment"]
        rules: [
            {
                id: "SEM-001"
                description: "Application version must be at least 1.0.0"
                severity: "high"
                expr: {
                    match: {
                        path: "version"
                        semver: {greaterThanOrEqual: "1.0.0"}
                    }
                }
                message: "Application version must be >= 1.0.0 for production"
            },
            {
                id: "SEM-002"
                description: "API version must be v2.x"
                severity: "critical"
                expr: {
                    match: {
                        path: "apiVersion"
                        semver: {constraint: "^2.0.0"}
                    }
                }
                message: "API version must be 2.x compatible"
            },
            {
                id: "SEM-003"
                description: "No alpha or beta releases in production"
                severity: "critical"
                expr: {
                    not: {
                        any: [
                            {match: {path: "version", contains: "-alpha"}},
                            {match: {path: "version", contains: "-beta"}},
                            {match: {path: "version", contains: "-rc"}}
                        ]
                    }
                }
                message: "Pre-release versions not allowed in production"
            }
        ]
        enforcement: action: "deny"
    }
}

// Date/time validation policy
datetimePolicy: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "datetime-policy"
        namespace: "advanced"
    }
    spec: {
        description: "Validates dates and expiration"
        target: resources: ["certificate", "secret", "deployment"]
        rules: [
            {
                id: "DATE-001"
                description: "Certificate must not be expired"
                severity: "critical"
                expr: {
                    match: {
                        path: "expiresAt"
                        datetime: {notExpired: true}
                    }
                }
                message: "Certificate has expired"
            },
            {
                id: "DATE-002"
                description: "Certificate must be valid for at least 30 days"
                severity: "high"
                expr: {
                    match: {
                        path: "expiresAt"
                        datetime: {expiresAfterDays: 30}
                    }
                }
                message: "Certificate expires in less than 30 days"
            },
            {
                id: "DATE-003"
                description: "Deployment must be created after 2024"
                severity: "low"
                expr: {
                    match: {
                        path: "metadata.createdAt"
                        datetime: {after: "2024-01-01"}
                    }
                }
                message: "Deployment predates 2024"
            }
        ]
        enforcement: action: "deny"
    }
}

// Cross-field comparison policy
crossFieldPolicy: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "cross-field-policy"
        namespace: "advanced"
    }
    spec: {
        description: "Validates relationships between fields"
        target: resources: ["autoscaler", "deployment"]
        rules: [
            {
                id: "CROSS-001"
                description: "minReplicas must be <= maxReplicas"
                severity: "critical"
                expr: {
                    compare: {
                        left: {path: "spec.minReplicas"}
                        op: "<="
                        right: {path: "spec.maxReplicas"}
                    }
                }
                message: "minReplicas cannot be greater than maxReplicas"
            },
            {
                id: "CROSS-002"
                description: "Memory request must be <= memory limit"
                severity: "high"
                expr: {
                    compare: {
                        left: {path: "spec.resources.requests.memory"}
                        op: "<="
                        right: {path: "spec.resources.limits.memory"}
                    }
                }
                message: "Memory request exceeds memory limit"
            }
        ]
        enforcement: action: "deny"
    }
}