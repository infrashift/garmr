// examples/policies.cue
// Example policies demonstrating Q Policy Agent capabilities
package examples

import "github.com/yourorg/q-policy-agent/schemas:policy"

// noPrivilegedContainers prevents containers from running in privileged mode
noPrivilegedContainers: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "no-privileged-containers"
		namespace: "security"
		labels: {
			"category":   "container-security"
			"compliance": "cis-benchmark"
			"cis-id":     "5.2.1"
		}
		annotations: {
			"docs": "https://example.com/policies/no-privileged"
		}
	}
	spec: {
		description: "Containers must not run in privileged mode"

		target: {
			resources: [{
				apiGroup: "apps"
				kind:     "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet"
			}, {
				apiGroup: ""
				kind:     "Pod"
			}]
		}

		rules: [{
			id:          "SEC-001"
			description: "Container privileged mode must be false"
			severity:    "critical"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: {
						any: [{
							absent: "item.securityContext.privileged"
						}, {
							compare: {
								left: path:    "item.securityContext.privileged"
								op:            "=="
								right: literal: false
							}
						}]
					}
				}
			}
			message: "Container '{{.container.name}}' must not run in privileged mode"
			remediation: """
				Set securityContext.privileged to false:
				  securityContext:
				    privileged: false
				"""
		}, {
			id:          "SEC-002"
			description: "Init container privileged mode must be false"
			severity:    "critical"
			expr: {
				forEach: {
					collection: "spec.initContainers"
					as:         "container"
					expr: {
						any: [{
							absent: "item.securityContext.privileged"
						}, {
							compare: {
								left: path:    "item.securityContext.privileged"
								op:            "=="
								right: literal: false
							}
						}]
					}
				}
			}
			message: "Init container '{{.container.name}}' must not run in privileged mode"
		}]

		enforcement: {
			action: "deny"
			exceptions: [{
				name:   "kube-system-exempt"
				reason: "System components may require elevated privileges"
				match: {
					namespaces: ["kube-system", "kube-node-lease"]
				}
			}, {
				name:   "cni-plugins"
				reason: "CNI plugins require privileged access for network setup"
				match: {
					labels: "app.kubernetes.io/component": "cni"
				}
			}]
		}
	}
}

// requiredLabels ensures resources have required labels
requiredLabels: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "required-labels"
		namespace: "governance"
		labels: {
			"category": "metadata"
		}
	}
	spec: {
		description: "Resources must have required labels for tracking and management"

		target: {
			resources: [{
				kind: "Deployment" | "StatefulSet" | "DaemonSet" | "Service" | "ConfigMap"
			}]
			conditions: [{
				expr: {
					// Only apply to non-system namespaces
					not: {
						match: {
							path:    "metadata.namespace"
							pattern: "^kube-"
						}
					}
				}
			}]
		}

		rules: [{
			id:          "GOV-001"
			description: "Must have 'app' label"
			severity:    "high"
			expr: exists: "metadata.labels.app"
			message:     "Resource must have 'app' label"
		}, {
			id:          "GOV-002"
			description: "Must have 'owner' label"
			severity:    "medium"
			expr: exists: "metadata.labels.owner"
			message:     "Resource must have 'owner' label for accountability"
		}, {
			id:          "GOV-003"
			description: "Must have 'environment' label"
			severity:    "medium"
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
			message: "Resource must have 'environment' label with value: dev, staging, or prod"
		}]

		enforcement: {
			action: "warn"
		}
	}
}

// imageRegistry restricts container images to allowed registries
imageRegistry: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "allowed-registries"
		namespace: "security"
		labels: {
			"category":   "supply-chain"
			"compliance": "soc2"
		}
	}
	spec: {
		description: "Container images must come from approved registries"

		target: {
			resources: [{
				kind: "Pod" | "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob"
			}]
		}

		rules: [{
			id:          "SEC-010"
			description: "Images must be from allowed registries"
			severity:    "critical"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: {
						any: [{
							match: {
								path:    "item.image"
								pattern: "^gcr\\.io/our-project/"
							}
						}, {
							match: {
								path:    "item.image"
								pattern: "^us-docker\\.pkg\\.dev/our-project/"
							}
						}, {
							match: {
								path:    "item.image"
								pattern: "^ghcr\\.io/our-org/"
							}
						}]
					}
				}
			}
			message: "Container '{{.container.name}}' uses image from untrusted registry"
			url:     "https://wiki.example.com/approved-registries"
		}, {
			id:          "SEC-011"
			description: "Images must not use 'latest' tag"
			severity:    "high"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: {
						not: {
							match: {
								path:    "item.image"
								pattern: ":latest$"
							}
						}
					}
				}
			}
			message: "Container '{{.container.name}}' uses 'latest' tag - use specific version"
		}, {
			id:          "SEC-012"
			description: "Images should have digest"
			severity:    "low"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: {
						match: {
							path:    "item.image"
							pattern: "@sha256:"
						}
					}
				}
			}
			message: "Container '{{.container.name}}' should use image digest for immutability"
		}]

		enforcement: {
			action: "deny"
			exceptions: [{
				name:   "local-development"
				reason: "Local development may use local registry"
				match: {
					namespaces: ["dev", "local"]
				}
				expiry: "2025-12-31T23:59:59Z"
			}]
		}
	}
}

// resourceLimits ensures containers have resource limits
resourceLimits: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "resource-limits"
		namespace: "governance"
		labels: {
			"category": "resource-management"
		}
	}
	spec: {
		description: "Containers must have resource requests and limits defined"

		target: {
			resources: [{
				kind: "Pod" | "Deployment" | "StatefulSet" | "DaemonSet"
			}]
		}

		rules: [{
			id:          "RES-001"
			description: "CPU limits must be set"
			severity:    "high"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: exists: "item.resources.limits.cpu"
				}
			}
			message: "Container '{{.container.name}}' must have CPU limits"
		}, {
			id:          "RES-002"
			description: "Memory limits must be set"
			severity:    "high"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: exists: "item.resources.limits.memory"
				}
			}
			message: "Container '{{.container.name}}' must have memory limits"
		}, {
			id:          "RES-003"
			description: "CPU requests must be set"
			severity:    "medium"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: exists: "item.resources.requests.cpu"
				}
			}
			message: "Container '{{.container.name}}' should have CPU requests"
		}, {
			id:          "RES-004"
			description: "Memory requests must be set"
			severity:    "medium"
			expr: {
				forEach: {
					collection: "spec.containers"
					as:         "container"
					expr: exists: "item.resources.requests.memory"
				}
			}
			message: "Container '{{.container.name}}' should have memory requests"
		}]

		enforcement: {
			action: "warn"
		}
	}
}

// networkPolicy requires network policies for namespaces
networkPolicy: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "require-network-policy"
		namespace: "security"
		labels: {
			"category":   "network"
			"compliance": "pci-dss"
		}
	}
	spec: {
		description: "Namespaces must have a default-deny network policy"

		target: {
			resources: [{
				kind: "Namespace"
			}]
			conditions: [{
				expr: {
					not: {
						compare: {
							left: path: "metadata.name"
							op:         "in"
							right: literal: ["kube-system", "kube-public", "kube-node-lease", "default"]
						}
					}
				}
			}]
		}

		rules: [{
			id:          "NET-001"
			description: "Namespace must have network-policy-configured annotation"
			severity:    "high"
			expr: {
				compare: {
					left: path: "metadata.annotations.\"network-policy-configured\""
					op:         "=="
					right: literal: "true"
				}
			}
			message:     "Namespace must have network policies configured"
			remediation: "Create a default-deny NetworkPolicy and add annotation 'network-policy-configured: true'"
		}]

		enforcement: {
			action: "audit"
		}
	}
}

// terraformPolicy for infrastructure validation
terraformPolicy: policy.#Policy & {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "terraform-s3-encryption"
		namespace: "infrastructure"
		labels: {
			"provider": "aws"
			"resource": "s3"
		}
	}
	spec: {
		description: "S3 buckets must have encryption enabled"

		target: {
			resources: [{
				kind: "aws_s3_bucket"
			}]
		}

		rules: [{
			id:          "AWS-001"
			description: "S3 bucket must have server-side encryption"
			severity:    "critical"
			expr: {
				any: [{
					exists: "server_side_encryption_configuration"
				}, {
					// Check for separate encryption resource
					ref: "data.aws_s3_bucket_server_side_encryption_configuration"
				}]
			}
			message: "S3 bucket '{{.bucket}}' must have server-side encryption enabled"
		}, {
			id:          "AWS-002"
			description: "S3 bucket must block public access"
			severity:    "critical"
			expr: {
				all: [{
					compare: {
						left: path:    "block_public_acls"
						op:            "=="
						right: literal: true
					}
				}, {
					compare: {
						left: path:    "block_public_policy"
						op:            "=="
						right: literal: true
					}
				}, {
					compare: {
						left: path:    "ignore_public_acls"
						op:            "=="
						right: literal: true
					}
				}, {
					compare: {
						left: path:    "restrict_public_buckets"
						op:            "=="
						right: literal: true
					}
				}]
			}
			message: "S3 bucket '{{.bucket}}' must block all public access"
		}, {
			id:          "AWS-003"
			description: "S3 bucket should have versioning enabled"
			severity:    "medium"
			expr: {
				compare: {
					left: path:    "versioning.0.enabled"
					op:            "=="
					right: literal: true
				}
			}
			message: "S3 bucket '{{.bucket}}' should have versioning enabled"
		}]

		enforcement: {
			action: "deny"
		}
	}
}
