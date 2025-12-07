// examples/namespace-organization.cue
// Namespace Organization Example
// Demonstrates how to organize policies using namespaces for different concerns
package namespaces

import "github.com/yourorg/q-policy-agent/schemas:policy"

// ============================================
// NAMESPACE STRATEGY
// ============================================
// 
// Namespaces provide logical grouping and access control boundaries.
// Common patterns:
//
// By Domain:
//   - security/         Security controls
//   - compliance/       Regulatory requirements  
//   - governance/       Organizational standards
//   - infrastructure/   Cloud resource policies
//   - release/          Release management
//
// By Team:
//   - platform/         Platform team policies
//   - security/         Security team policies
//   - sre/              SRE team policies
//   - product/          Product team policies
//
// By Environment:
//   - dev/              Development-specific
//   - staging/          Staging-specific
//   - prod/             Production-specific
//
// By Application:
//   - payments/         Payment service policies
//   - auth/             Auth service policies
//   - api-gateway/      API gateway policies
//
// ============================================

// ============================================
// SECURITY NAMESPACE
// Owned by: Security Team
// Purpose: Security controls and vulnerability management
// ============================================

securityContainerPolicy: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "container-security"
		namespace: "security"  // Security team namespace
		labels: {
			"owner":      "security-team"
			"compliance": "soc2,pci-dss"
			"scope":      "containers"
		}
		annotations: {
			"contact":     "security@example.com"
			"runbook":     "https://wiki.example.com/security/container-policy"
			"last-review": "2024-11-01"
		}
	}
	spec: {
		description: "Container security controls for all deployments"
		
		target: {
			resources: [{
				kind: "Deployment"
			}, {
				kind: "StatefulSet"
			}, {
				kind: "DaemonSet"
			}]
		}
		
		evaluation: {
			order:    "priority"
			failFast: false  // Evaluate all rules, report all violations
		}
		
		rules: [{
			id:          "SEC-001"
			description: "Containers must not run as root"
			severity:    "critical"
			priority:    100
			category:    "container-security"
			tags:        ["root", "privilege", "cis-benchmark"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						any: [{
							exists: "item.securityContext.runAsNonRoot"
							compare: {
								left: path:    "item.securityContext.runAsNonRoot"
								op:            "=="
								right: literal: true
							}
						}, {
							all: [{
								exists: "item.securityContext.runAsUser"
							}, {
								compare: {
									left: path: "item.securityContext.runAsUser"
									op:         ">"
									right: literal: 0
								}
							}]
						}]
					}
				}
			}
			message:     "Container '{{.container.name}}' must not run as root"
			remediation: "Set securityContext.runAsNonRoot: true or runAsUser > 0"
		}, {
			id:          "SEC-002"
			description: "Containers must drop all capabilities"
			severity:    "high"
			priority:    110
			category:    "container-security"
			tags:        ["capabilities", "privilege", "cis-benchmark"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						all: [{
							exists: "item.securityContext.capabilities.drop"
						}, {
							contains: {
								path: "item.securityContext.capabilities.drop"
								value: literal: "ALL"
							}
						}]
					}
				}
			}
			message:     "Container '{{.container.name}}' must drop ALL capabilities"
			remediation: "Add securityContext.capabilities.drop: ['ALL']"
		}, {
			id:          "SEC-003"
			description: "Containers must have read-only root filesystem"
			severity:    "medium"
			priority:    120
			category:    "container-security"
			tags:        ["filesystem", "immutable", "cis-benchmark"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						compare: {
							left: path:    "item.securityContext.readOnlyRootFilesystem"
							op:            "=="
							right: literal: true
						}
					}
				}
			}
			message:     "Container '{{.container.name}}' should have read-only root filesystem"
			remediation: "Set securityContext.readOnlyRootFilesystem: true"
		}]
		
		enforcement: {
			action: "deny"
			exceptions: [{
				name:   "legacy-apps"
				reason: "Legacy applications pending migration"
				match: {
					labels: {
						"security-exception": "legacy"
					}
				}
				expiry: "2025-06-01T00:00:00Z"
			}]
		}
	}
}

securityNetworkPolicy: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "network-security"
		namespace: "security"
		labels: {
			"owner":      "security-team"
			"compliance": "soc2"
			"scope":      "network"
		}
	}
	spec: {
		description: "Network security controls"
		
		target: {
			resources: [{
				kind: "Service"
			}, {
				kind: "Ingress"
			}]
		}
		
		rules: [{
			id:          "SEC-010"
			description: "Services must not expose NodePort in production"
			severity:    "high"
			priority:    100
			category:    "network-security"
			tags:        ["nodeport", "exposure"]
			expr: {
				any: [{
					// Not a production namespace
					not: {
						match: {
							path:    "metadata.namespace"
							pattern: "^prod"
						}
					}
				}, {
					// Not a NodePort service
					not: {
						compare: {
							left: path:    "spec.type"
							op:            "=="
							right: literal: "NodePort"
						}
					}
				}]
			}
			message: "NodePort services are not allowed in production namespaces"
		}]
		
		enforcement: {
			action: "deny"
		}
	}
}

// ============================================
// COMPLIANCE NAMESPACE
// Owned by: Compliance/GRC Team
// Purpose: Regulatory and audit requirements
// ============================================

complianceDataResidency: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "data-residency"
		namespace: "compliance"
		labels: {
			"owner":      "compliance-team"
			"regulation": "gdpr"
			"scope":      "data"
		}
		annotations: {
			"audit-frequency": "quarterly"
			"control-id":      "GDPR-44"
		}
	}
	spec: {
		description: "GDPR data residency requirements for EU customer data"
		
		target: {
			resources: [{
				kind: "PersistentVolumeClaim"
				labels: {
					"data-classification": "pii"
				}
			}, {
				kind: "StatefulSet"
				labels: {
					"data-classification": "pii"
				}
			}]
		}
		
		evaluation: {
			order:    "severity"
			failFast: true  // Stop on first compliance violation
		}
		
		rules: [{
			id:          "GDPR-001"
			description: "EU PII data must be stored in EU regions"
			severity:    "critical"
			priority:    10
			category:    "data-residency"
			tags:        ["gdpr", "pii", "eu"]
			continueOnFail: false  // Critical compliance - halt on failure
			expr: {
				any: [{
					// Not EU data
					not: {
						compare: {
							left: path:    "metadata.labels.data-region"
							op:            "=="
							right: literal: "eu"
						}
					}
				}, {
					// EU data in EU region
					compare: {
						left: path: "spec.storageClassName"
						op:         "in"
						right: literal: [
							"eu-west-1-gp3",
							"eu-central-1-gp3",
							"eu-north-1-gp3",
						]
					}
				}]
			}
			message:     "EU PII data must use EU storage classes"
			remediation: "Use storage class: eu-west-1-gp3, eu-central-1-gp3, or eu-north-1-gp3"
		}]
		
		enforcement: {
			action: "deny"
		}
	}
}

complianceEncryption: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "encryption-at-rest"
		namespace: "compliance"
		labels: {
			"owner":      "compliance-team"
			"regulation": "pci-dss,hipaa"
			"scope":      "encryption"
		}
		annotations: {
			"control-id": "PCI-DSS-3.4,HIPAA-164.312(a)(2)(iv)"
		}
	}
	spec: {
		description: "Encryption at rest requirements for sensitive data"
		
		target: {
			resources: [{
				kind: "PersistentVolumeClaim"
				labels: {
					"data-classification": "sensitive"
				}
			}]
		}
		
		rules: [{
			id:          "ENC-001"
			description: "Sensitive data must use encrypted storage class"
			severity:    "critical"
			priority:    10
			category:    "encryption"
			tags:        ["encryption", "pci-dss", "hipaa"]
			continueOnFail: false
			expr: {
				match: {
					path:    "spec.storageClassName"
					pattern: "-encrypted$"
				}
			}
			message:     "Sensitive data must use encrypted storage class"
			remediation: "Use a storage class ending in '-encrypted' (e.g., gp3-encrypted)"
		}]
		
		enforcement: {
			action: "deny"
		}
	}
}

// ============================================
// GOVERNANCE NAMESPACE
// Owned by: Platform Team
// Purpose: Organizational standards and best practices
// ============================================

governanceLabeling: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "resource-labeling"
		namespace: "governance"
		labels: {
			"owner": "platform-team"
			"scope": "metadata"
		}
	}
	spec: {
		description: "Required labels for all Kubernetes resources"
		
		target: {
			resources: [{
				kind: "Deployment"
			}, {
				kind: "StatefulSet"
			}, {
				kind: "Service"
			}, {
				kind: "ConfigMap"
			}]
			// Exclude system namespaces
			conditions: [{
				expr: {
					not: {
						match: {
							path:    "metadata.namespace"
							pattern: "^(kube-|istio-|cert-manager)"
						}
					}
				}
			}]
		}
		
		evaluation: {
			order:    "priority"
			failFast: false
		}
		
		rules: [{
			id:          "GOV-001"
			description: "Resources must have 'app' label"
			severity:    "high"
			priority:    100
			category:    "labeling"
			tags:        ["labels", "discovery"]
			expr: {
				exists: "metadata.labels.app"
			}
			message: "Resource must have 'app' label for service discovery"
		}, {
			id:          "GOV-002"
			description: "Resources must have 'owner' label"
			severity:    "high"
			priority:    100
			category:    "labeling"
			tags:        ["labels", "ownership"]
			expr: {
				exists: "metadata.labels.owner"
			}
			message: "Resource must have 'owner' label for accountability"
		}, {
			id:          "GOV-003"
			description: "Resources must have 'environment' label"
			severity:    "medium"
			priority:    110
			category:    "labeling"
			tags:        ["labels", "environment"]
			expr: {
				all: [{
					exists: "metadata.labels.environment"
				}, {
					compare: {
						left: path: "metadata.labels.environment"
						op:         "in"
						right: literal: ["dev", "staging", "prod"]
					}
				}]
			}
			message: "Resource must have valid 'environment' label (dev, staging, prod)"
		}, {
			id:          "GOV-004"
			description: "Resources should have 'cost-center' label"
			severity:    "low"
			priority:    200
			category:    "labeling"
			tags:        ["labels", "cost"]
			expr: {
				exists: "metadata.labels.cost-center"
			}
			message: "Resource should have 'cost-center' label for billing"
		}]
		
		enforcement: {
			action: "warn"
		}
	}
}

governanceResourceQuotas: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "resource-quotas"
		namespace: "governance"
		labels: {
			"owner": "platform-team"
			"scope": "resources"
		}
	}
	spec: {
		description: "Resource quota and limit requirements"
		
		target: {
			resources: [{
				kind: "Deployment"
			}, {
				kind: "StatefulSet"
			}]
		}
		
		rules: [{
			id:          "GOV-010"
			description: "Containers must have resource limits"
			severity:    "high"
			priority:    100
			category:    "resources"
			tags:        ["limits", "quota"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						all: [{
							exists: "item.resources.limits.cpu"
						}, {
							exists: "item.resources.limits.memory"
						}]
					}
				}
			}
			message: "All containers must have CPU and memory limits"
		}, {
			id:          "GOV-011"
			description: "Containers must have resource requests"
			severity:    "medium"
			priority:    110
			category:    "resources"
			tags:        ["requests", "scheduling"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						all: [{
							exists: "item.resources.requests.cpu"
						}, {
							exists: "item.resources.requests.memory"
						}]
					}
				}
			}
			message: "All containers should have CPU and memory requests for proper scheduling"
		}]
		
		enforcement: {
			action: "deny"
		}
	}
}

// ============================================
// SRE NAMESPACE
// Owned by: SRE Team
// Purpose: Reliability and observability requirements
// ============================================

sreObservability: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "observability"
		namespace: "sre"
		labels: {
			"owner": "sre-team"
			"scope": "observability"
		}
	}
	spec: {
		description: "Observability requirements for production workloads"
		
		target: {
			resources: [{
				kind: "Deployment"
				labels: {
					"environment": "prod"
				}
			}]
		}
		
		rules: [{
			id:          "SRE-001"
			description: "Production deployments must have liveness probe"
			severity:    "high"
			priority:    100
			category:    "probes"
			tags:        ["liveness", "health"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						exists: "item.livenessProbe"
					}
				}
			}
			message: "Production containers must have liveness probes"
		}, {
			id:          "SRE-002"
			description: "Production deployments must have readiness probe"
			severity:    "high"
			priority:    100
			category:    "probes"
			tags:        ["readiness", "health"]
			expr: {
				forEach: {
					collection: "spec.template.spec.containers"
					as:         "container"
					mode:       "all"
					expr: {
						exists: "item.readinessProbe"
					}
				}
			}
			message: "Production containers must have readiness probes"
		}, {
			id:          "SRE-003"
			description: "Production deployments must have prometheus annotations"
			severity:    "medium"
			priority:    200
			category:    "metrics"
			tags:        ["prometheus", "monitoring"]
			expr: {
				all: [{
					exists: "spec.template.metadata.annotations.\"prometheus.io/scrape\""
				}, {
					compare: {
						left: path:    "spec.template.metadata.annotations.\"prometheus.io/scrape\""
						op:            "=="
						right: literal: "true"
					}
				}]
			}
			message: "Production deployments must be scraped by Prometheus"
		}]
		
		enforcement: {
			action: "warn"
		}
	}
}

sreHighAvailability: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "high-availability"
		namespace: "sre"
		labels: {
			"owner": "sre-team"
			"scope": "availability"
		}
	}
	spec: {
		description: "High availability requirements for production"
		
		target: {
			resources: [{
				kind: "Deployment"
				labels: {
					"environment":      "prod"
					"availability-tier": "critical"
				}
			}]
		}
		
		rules: [{
			id:          "SRE-010"
			description: "Critical services must have minimum 3 replicas"
			severity:    "critical"
			priority:    100
			category:    "availability"
			tags:        ["replicas", "ha"]
			expr: {
				compare: {
					left: path: "spec.replicas"
					op:         ">="
					right: literal: 3
				}
			}
			message: "Critical production services must have at least 3 replicas"
		}, {
			id:          "SRE-011"
			description: "Critical services must have pod anti-affinity"
			severity:    "high"
			priority:    110
			category:    "availability"
			tags:        ["affinity", "ha", "spread"]
			expr: {
				exists: "spec.template.spec.affinity.podAntiAffinity"
			}
			message: "Critical services must spread pods across nodes"
		}, {
			id:          "SRE-012"
			description: "Critical services must have PodDisruptionBudget"
			severity:    "high"
			priority:    120
			category:    "availability"
			tags:        ["pdb", "ha"]
			// Note: This would typically check for a corresponding PDB resource
			expr: {
				exists: "metadata.annotations.\"pdb-configured\""
			}
			message: "Critical services must have a PodDisruptionBudget"
		}]
		
		enforcement: {
			action: "deny"
		}
	}
}

// ============================================
// NAMESPACE HIERARCHY EXAMPLE
// Shows how to query policies across namespaces
// ============================================

// Query examples (for CLI/API):
//
// List all policies in security namespace:
//   q policy list -n security
//
// Evaluate against all policies in multiple namespaces:
//   q eval --input deploy.json -n security -n compliance -n governance
//
// Evaluate against all policies (all namespaces):
//   q eval --input deploy.json --all-namespaces
//
// Filter by label across namespaces:
//   q policy list --all-namespaces -l owner=security-team
//
// Get policies for specific compliance:
//   q policy list --all-namespaces -l compliance=pci-dss

// ============================================
// NAMESPACE ACCESS CONTROL (RBAC Example)
// ============================================

// In a real deployment, namespace access would be controlled via RBAC:
//
// # Security team can manage security namespace
// apiVersion: rbac.authorization.k8s.io/v1
// kind: Role
// metadata:
//   name: security-policy-admin
//   namespace: security
// rules:
// - apiGroups: ["policy.q.io"]
//   resources: ["policies"]
//   verbs: ["*"]
//
// # Platform team can read all namespaces, write governance
// apiVersion: rbac.authorization.k8s.io/v1
// kind: ClusterRole
// metadata:
//   name: platform-policy-admin
// rules:
// - apiGroups: ["policy.q.io"]
//   resources: ["policies"]
//   verbs: ["get", "list", "watch"]
// - apiGroups: ["policy.q.io"]
//   resources: ["policies"]
//   resourceNames: ["governance/*"]
//   verbs: ["*"]
