// schemas/hashicorp.cue
// CUE schemas for HashiCorp Vault and Consul policy integration.
// These schemas define policies for external authorization of Vault and Consul operations.
package config

// ============================================
// VAULT POLICY SCHEMAS
// ============================================

// VaultPolicy defines a policy for Vault authorization.
#VaultPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	
	metadata: {
		name:      string
		namespace: string | *"vault"
		labels: {
			"policy.garmr.io/target": "vault"
			...
		}
		...
	}
	
	spec: {
		target: {
			system: "vault"
			...
		}
		
		// Vault-specific input schema
		inputSchema: #VaultInputSchema
		
		rules: [...#VaultRule]
		...
	}
}

// VaultInputSchema defines expected input for Vault authorization.
#VaultInputSchema: {
	// Operation being performed
	operation: "create" | "read" | "update" | "delete" | "list"
	
	// Path being accessed
	path: string
	
	// Token metadata
	token: {
		display_name: string
		policies: [...string]
		entity_id?: string
		groups?: [...string]
		metadata?: [string]: string
	}
	
	// Request metadata
	request: {
		remote_addr: string
		timestamp: string
		request_id: string
		namespace?: string
	}
	
	// Request data (optional, may be redacted)
	data?: {...}
}

// VaultRule defines a rule for Vault authorization.
#VaultRule: {
	id:          string & =~"^VAULT-[0-9]{3}$"
	description: string
	severity:    "critical" | "high" | "medium" | "low"
	category:    "access" | "secrets" | "auth" | "audit" | "governance"
	
	condition:   string
	message:     string
	remediation?: string
	references?: [...string]
}

// ============================================
// CONSUL POLICY SCHEMAS
// ============================================

// ConsulPolicy defines a policy for Consul authorization.
#ConsulPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	
	metadata: {
		name:      string
		namespace: string | *"consul"
		labels: {
			"policy.garmr.io/target": "consul"
			...
		}
		...
	}
	
	spec: {
		target: {
			system: "consul"
			...
		}
		
		// Consul-specific input schema
		inputSchema: #ConsulInputSchema
		
		rules: [...#ConsulRule]
		...
	}
}

// ConsulInputSchema defines expected input for Consul authorization.
#ConsulInputSchema: {
	// Operation being performed
	operation: string
	
	// Resource being accessed
	resource: {
		type:       "service" | "kv" | "intention" | "config"
		name:       string
		namespace?: string
		partition?: string
		datacenter?: string
		data?: {...}
	}
	
	// Identity of requester
	identity: {
		service_name?: string
		service_id?: string
		namespace?: string
		partition?: string
		spiffe_id?: string
		token_meta?: [string]: string
	}
	
	// Request context
	context: {
		remote_addr: string
		timestamp: string
		request_id: string
		datacenter: string
	}
}

// ConsulIntentionInput for service-to-service authorization.
#ConsulIntentionInput: {
	source: {
		name:      string
		namespace: string | *"default"
		partition: string | *"default"
	}
	destination: {
		name:      string
		namespace: string | *"default"
		partition: string | *"default"
	}
	action: "allow" | "deny"
}

// ConsulRule defines a rule for Consul authorization.
#ConsulRule: {
	id:          string & =~"^CONSUL-[0-9]{3}$"
	description: string
	severity:    "critical" | "high" | "medium" | "low"
	category:    "service" | "kv" | "intention" | "config" | "governance"
	
	condition:   string
	message:     string
	remediation?: string
	references?: [...string]
}

// ============================================
// EXAMPLE POLICIES
// ============================================

// Example: Vault secrets engine access control
_vaultSecretsPolicy: #VaultPolicy & {
	metadata: {
		name:      "vault-secrets-access"
		namespace: "vault"
		labels: {
			"policy.garmr.io/target": "vault"
			"vault/engine":       "kv"
		}
	}
	
	spec: {
		target: {
			system:      "vault"
			environment: "production"
		}
		
		rules: [
			{
				id:          "VAULT-001"
				description: "Restrict production secrets to authorized services"
				severity:    "critical"
				category:    "secrets"
				condition:   """
					!(input.path =~ "^secret/data/prod/") || 
					"prod-access" in input.token.policies
					"""
				message:     "Access to production secrets requires prod-access policy"
				remediation: "Request prod-access policy from security team"
			},
			{
				id:          "VAULT-002"
				description: "Audit all secret deletions"
				severity:    "high"
				category:    "audit"
				condition:   """
					input.operation != "delete" ||
					"secret-admin" in input.token.policies
					"""
				message:     "Secret deletion requires secret-admin policy"
				remediation: "Use secret versioning instead of deletion"
			},
			{
				id:          "VAULT-003"
				description: "Block access from unknown IP ranges"
				severity:    "critical"
				category:    "access"
				condition:   """
					input.request.remote_addr =~ "^10\\." ||
					input.request.remote_addr =~ "^192\\.168\\."
					"""
				message:     "Access denied from external IP"
				remediation: "Connect via VPN or internal network"
			},
		]
	}
}

// Example: Consul service registration policy
_consulServicePolicy: #ConsulPolicy & {
	metadata: {
		name:      "consul-service-registration"
		namespace: "consul"
		labels: {
			"policy.garmr.io/target": "consul"
			"consul/operation":   "service"
		}
	}
	
	spec: {
		target: {
			system:      "consul"
			environment: "production"
		}
		
		rules: [
			{
				id:          "CONSUL-001"
				description: "Services must use approved naming convention"
				severity:    "high"
				category:    "service"
				condition:   """
					input.resource.name =~ "^[a-z][a-z0-9-]*$" &&
					len(input.resource.name) <= 63
					"""
				message:     "Service name must be lowercase alphanumeric with hyphens"
				remediation: "Rename service to follow convention: ^[a-z][a-z0-9-]*$"
			},
			{
				id:          "CONSUL-002"
				description: "Production services must have health checks"
				severity:    "critical"
				category:    "service"
				condition:   """
					input.resource.data.check != null ||
					input.resource.data.checks != null ||
					input.context.datacenter != "dc1-prod"
					"""
				message:     "Production services require health checks"
				remediation: "Add HTTP, TCP, or TTL health check to service definition"
			},
			{
				id:          "CONSUL-003"
				description: "Services must specify namespace"
				severity:    "medium"
				category:    "governance"
				condition:   """
					input.resource.namespace != "" &&
					input.resource.namespace != "default"
					"""
				message:     "Services should not use default namespace"
				remediation: "Create and specify appropriate namespace for the service"
			},
		]
	}
}

// Example: Consul intentions policy
_consulIntentionPolicy: #ConsulPolicy & {
	metadata: {
		name:      "consul-intentions"
		namespace: "consul"
		labels: {
			"policy.garmr.io/target":  "consul"
			"consul/operation":    "intention"
		}
	}
	
	spec: {
		target: {
			system: "consul"
		}
		
		rules: [
			{
				id:          "CONSUL-010"
				description: "Database services can only be accessed by known consumers"
				severity:    "critical"
				category:    "intention"
				condition:   """
					!(input.destination.name =~ "-db$") ||
					input.source.name =~ "^api-" ||
					input.source.name =~ "^worker-"
					"""
				message:     "Database services restricted to API and worker services"
				remediation: "Request database access through service catalog"
			},
			{
				id:          "CONSUL-011"
				description: "Cross-namespace intentions require approval"
				severity:    "high"
				category:    "intention"
				condition:   """
					input.source.namespace == input.destination.namespace ||
					input.source.namespace == "platform"
					"""
				message:     "Cross-namespace intentions require security review"
				remediation: "Submit cross-namespace access request to security team"
			},
		]
	}
}

// ============================================
// PLUGIN CONFIGURATION SCHEMAS
// ============================================

// VaultAuthzPluginConfig configures the Vault authorization plugin.
#VaultAuthzPluginConfig: {
	enabled: bool | *true
	
	// Vault server address
	vaultAddr: string | *"http://127.0.0.1:8200"
	
	// Listen address for authorization webhook
	listenAddr: string | *":8280"
	
	// Q namespace for Vault policies
	policyNamespace: string | *"vault"
	
	// Default policy when no mapping matches
	defaultPolicy: string | *"vault-default"
	
	// Path to policy mappings
	policyMapping: [string]: string
	
	// TLS configuration
	tls: {
		enabled:    bool | *false
		certFile:   string | *""
		keyFile:    string | *""
		caFile:     string | *""
		skipVerify: bool | *false
	}
	
	// Decision caching
	cache: {
		enabled: bool | *true
		ttl:     string | *"5m"
		maxSize: int | *10000
	}
	
	// Audit configuration
	audit: {
		enabled:       bool | *true
		includeInput:  bool | *false
		redactSecrets: bool | *true
	}
}

// ConsulAuthzPluginConfig configures the Consul authorization plugin.
#ConsulAuthzPluginConfig: {
	enabled: bool | *true
	
	// Consul server address
	consulAddr: string | *"http://127.0.0.1:8500"
	
	// Listen address for authorization webhook
	listenAddr: string | *":8281"
	
	// Q namespace for Consul policies
	policyNamespace: string | *"consul"
	
	// Datacenter
	datacenter: string | *"dc1"
	
	// Policy mappings by operation type
	policies: {
		serviceRegister:   string | *"consul-service-register"
		serviceDeregister: string | *"consul-service-deregister"
		intention:         string | *"consul-intention"
		kvRead:            string | *"consul-kv-read"
		kvWrite:           string | *"consul-kv-write"
		configEntry:       string | *"consul-config-entry"
		default:           string | *"consul-default"
	}
	
	// TLS configuration
	tls: {
		enabled:    bool | *false
		certFile:   string | *""
		keyFile:    string | *""
		caFile:     string | *""
		skipVerify: bool | *false
	}
}
