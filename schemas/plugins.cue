// schemas/plugins.cue
// Plugin Configuration Schema
// Defines how plugins are configured and loaded in Q Policy Agent
package config

// PluginConfig defines plugin management settings.
#PluginConfig: {
	// Enable plugin system (default: true)
	enabled: bool | *true
	
	// Directory for external plugins (.so/.dylib files)
	pluginDir: string | *"/plugins"
	
	// Security settings
	security: #PluginSecurityConfig
	
	// Registered plugins and their configurations
	plugins: [string]: #PluginEntry
}

#PluginSecurityConfig: {
	// Only allow explicitly listed plugins
	// When true, only plugins in 'allowed' list can load
	restrictToAllowed: bool | *false
	
	// Allowed plugin names (whitelist)
	allowed: [...string] | *[]
	
	// Blocked plugin names (blacklist, takes precedence)
	blocked: [...string] | *[]
	
	// Allow loading external plugins (set false for maximum security)
	allowExternal: bool | *true
	
	// Signature verification settings
	signing: #SigningConfig
}

// SigningConfig configures Ed25519 signature verification for plugins.
#SigningConfig: {
	// Require valid signatures for all external plugins
	// If true, unsigned plugins will not load
	required: bool | *false
	
	// Path to file containing trusted Ed25519 public keys
	// Format: one key per line, base64-encoded, optional comment
	trustedKeysFile: string | *""
	
	// Inline trusted keys (alternative to file)
	trustedKeys: [...#TrustedKey] | *[]
	
	// Reject plugins signed with untrusted keys
	// If false, untrusted signatures are treated as unsigned
	rejectUntrustedKeys: bool | *true
}

// TrustedKey represents a trusted Ed25519 public key.
#TrustedKey: {
	// Base64-encoded Ed25519 public key (32 bytes)
	publicKey: string
	
	// Human-readable description
	comment: string | *""
}

#PluginEntry: {
	// Enable this plugin
	enabled: bool | *true
	
	// Plugin type
	type: #PluginType
	
	// Plugin-specific configuration
	config: {...}
}

#PluginType: "storage" | "auth" | "notifier" | "function"

// ============================================
// BUILT-IN PLUGINS
// ============================================

// These are always available (compiled into Q)
#BuiltinPlugins: {
	// Filesystem storage - always included
	filesystem: #PluginEntry & {
		type: "storage"
		config: #FilesystemPluginConfig
	}
}

#FilesystemPluginConfig: {
	root:           string | *"/policies"
	followSymlinks: bool | *false
}

// ============================================
// OPTIONAL PLUGINS (loaded from pluginDir)
// ============================================

// S3/MinIO storage plugin
#S3PluginConfig: {
	endpoint:         string | *""
	region:           string | *"us-east-1"
	bucket:           string
	accessKeyId:      string | *""
	secretAccessKey:  string | *""
	useSsl:           bool | *true
	pollInterval:     string | *"10s"
	useSha256:        bool | *false
}

// DuckDB storage plugin (embedded analytics database)
#DuckDBPluginConfig: {
	// Path to DuckDB database file
	database: string | *":memory:"
	
	// Table name for policies
	tableName: string | *"policies"
	
	// Read-only mode
	readOnly: bool | *true
	
	// Connection pool size
	poolSize: int | *4
}

// Consul storage plugin
#ConsulPluginConfig: {
	// Consul address
	address: string | *"localhost:8500"
	
	// KV path prefix for policies
	prefix: string | *"q/policies"
	
	// Datacenter
	datacenter: string | *""
	
	// ACL token
	token: string | *""
	
	// Use TLS
	useTls: bool | *false
	
	// Watch for changes (uses Consul blocking queries)
	watch: bool | *true
}

// GCS storage plugin
#GCSPluginConfig: {
	bucket:          string
	project:         string | *""
	credentialsFile: string | *""
	pollInterval:    string | *"10s"
}

// Azure Blob storage plugin
#AzureBlobPluginConfig: {
	accountName:        string
	container:          string
	accountKey:         string | *""
	connectionString:   string | *""
	useManagedIdentity: bool | *false
	pollInterval:       string | *"10s"
}

// ============================================
// EXAMPLE CONFIGURATIONS
// ============================================

// Minimal configuration (filesystem only)
_minimalPluginConfig: #PluginConfig & {
	enabled: true
	plugins: {
		filesystem: {
			enabled: true
			type:    "storage"
			config: {
				root: "/policies"
			}
		}
	}
}

// Production with MinIO
_productionMinIOConfig: #PluginConfig & {
	enabled:   true
	pluginDir: "/opt/q/plugins"
	
	security: {
		restrictToAllowed: true
		allowed: ["filesystem", "s3"]
		
		signing: {
			// Require signatures in production
			required: true
			
			// Load trusted keys from file
			trustedKeysFile: "/etc/q/trusted-keys"
			
			// Or inline (CI/CD generated)
			trustedKeys: [{
				publicKey: "MCowBQYDK2VwAyEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
				comment:   "Production Plugin Signing Key"
			}]
			
			// Reject plugins signed with unknown keys
			rejectUntrustedKeys: true
		}
	}
	
	plugins: {
		filesystem: {
			enabled: true
			type:    "storage"
			config: root: "/policies"
		}
		s3: {
			enabled: true
			type:    "storage"
			config: #S3PluginConfig & {
				endpoint: "minio.storage.svc:9000"
				bucket:   "q-policies"
				useSsl:   false
			}
		}
	}
}

// High-security configuration
_highSecurityConfig: #PluginConfig & {
	enabled:   true
	pluginDir: "/opt/q/plugins"
	
	security: {
		// Only allow explicitly listed plugins
		restrictToAllowed: true
		allowed: ["filesystem"]
		
		// Block known problematic plugins
		blocked: []
		
		// Require checksums for any external plugins
		verifyChecksums: true
		
		// Disable external plugin loading entirely
		allowExternal: false
	}
	
	plugins: {
		filesystem: {
			enabled: true
			type:    "storage"
			config: root: "/policies"
		}
	}
}

// Multi-backend configuration
_multiBackendConfig: #PluginConfig & {
	enabled:   true
	pluginDir: "/opt/q/plugins"
	
	plugins: {
		filesystem: {
			enabled: true
			type:    "storage"
			config: root: "/local-policies"
		}
		s3: {
			enabled: true
			type:    "storage"
			config: #S3PluginConfig & {
				bucket: "shared-policies"
				region: "us-west-2"
			}
		}
		consul: {
			enabled: true
			type:    "storage"
			config: #ConsulPluginConfig & {
				address: "consul.service.consul:8500"
				prefix:  "q/policies/production"
				watch:   true
			}
		}
	}
}

// DuckDB for analytics/caching
_duckdbConfig: #PluginConfig & {
	enabled: true
	
	plugins: {
		filesystem: {
			enabled: true
			type:    "storage"
			config: root: "/policies"
		}
		duckdb: {
			enabled: true
			type:    "storage"
			config: #DuckDBPluginConfig & {
				database:  "/var/lib/q/policies.duckdb"
				tableName: "policies"
				readOnly:  true
			}
		}
	}
}

// ============================================
// FULL CONFIG WITH PLUGINS
// ============================================

// Updated main config schema with plugins
#ConfigWithPlugins: {
	apiVersion: "config.q.io/v1"
	
	server:        #ServerConfig
	plugins:       #PluginConfig
	policies:      #PolicyLoadingConfig  // Renamed from storage
	engine:        #EngineConfig
	logging:       #LoggingConfig
	observability: #ObservabilityConfig
}

// Policy loading now references a plugin
#PolicyLoadingConfig: {
	// Which storage plugin to use for policies
	storagePlugin: string | *"filesystem"
	
	// Fallback plugins (tried in order if primary fails)
	fallbackPlugins: [...string] | *[]
	
	// Namespace resolution
	namespaceStrategy: #NamespaceStrategy
	
	// Hot reload settings
	reload: #ReloadConfig
	
	// Policy sets
	policySets: #PolicySetConfig
	
	// Validation
	validation: {
		strict:         bool | *true
		validateSchema: bool | *true
		maxFileSize:    int | *10485760
	}
}

// Example: Complete production config
ProductionConfig: #ConfigWithPlugins & {
	apiVersion: "config.q.io/v1"
	
	server: {
		grpc: address: ":9090"
		http: address: ":8080"
	}
	
	plugins: {
		enabled:   true
		pluginDir: "/opt/q/plugins"
		
		security: {
			restrictToAllowed: true
			allowed: ["filesystem", "s3"]
			verifyChecksums:   true
			allowExternal:     true
		}
		
		plugins: {
			filesystem: {
				enabled: true
				type:    "storage"
				config: root: "/local-cache"
			}
			s3: {
				enabled: true
				type:    "storage"
				config: #S3PluginConfig & {
					endpoint: "minio.storage.svc:9000"
					bucket:   "q-policies"
					useSsl:   false
				}
			}
		}
	}
	
	policies: {
		storagePlugin:   "s3"
		fallbackPlugins: ["filesystem"]
		
		namespaceStrategy: {
			mode:           "hybrid"
			directoryDepth: 0
		}
		
		reload: {
			enabled: true
			strategy: mode: "poll"
		}
	}
	
	engine: {
		cache: enabled: true
	}
	
	logging: {
		level:  "info"
		format: "json"
	}
	
	observability: {
		metrics: enabled: true
	}
}
