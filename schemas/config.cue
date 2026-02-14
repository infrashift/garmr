// schemas/config.cue
// Garmr Configuration Schema
// Configuration is defined in CUE for type safety and validation
package config

import "time"

// Config is the root configuration for Garmr.
#Config: {
	// API version for configuration schema evolution
	apiVersion: "config.q.io/v1"
	
	// Server configuration
	server: #ServerConfig
	
	// Policy loading configuration
	policies: #PolicyConfig
	
	// Engine configuration
	engine: #EngineConfig
	
	// Logging configuration
	logging: #LoggingConfig
	
	// Metrics and observability
	observability: #ObservabilityConfig
}

// ServerConfig defines server settings.
#ServerConfig: {
	// gRPC server address
	grpc: {
		address: string | *":9090"
		// Maximum message size in bytes
		maxRecvSize: int | *16777216  // 16MB
		maxSendSize: int | *16777216
		// Keep-alive settings
		keepalive: {
			maxConnectionIdle:     string | *"5m"
			maxConnectionAge:      string | *"30m"
			maxConnectionAgeGrace: string | *"5s"
			time:                  string | *"1m"
			timeout:               string | *"20s"
		}
	}
	
	// HTTP gateway address
	http: {
		address: string | *":8080"
		// Read/write timeouts
		readTimeout:  string | *"30s"
		writeTimeout: string | *"30s"
		idleTimeout:  string | *"120s"
	}
	
	// TLS configuration (optional)
	tls?: {
		enabled:  bool | *false
		certFile: string
		keyFile:  string
		caFile?:  string
		// Mutual TLS
		clientAuth: "none" | "request" | "require" | *"none"
	}
}

// PolicyConfig defines how policies are loaded and managed.
#PolicyConfig: {
	// Root directory for policy files
	// In containers, this is typically a mounted volume
	rootDir: string | *"/policies"
	
	// File patterns to include (glob patterns)
	includePatterns: [...string] | *["**/*.cue"]
	
	// File patterns to exclude
	excludePatterns: [...string] | *["**/*_test.cue", "**/testdata/**"]
	
	// Namespace resolution strategy
	namespaceStrategy: #NamespaceStrategy
	
	// Hot reload configuration
	reload: #ReloadConfig
	
	// Policy set configuration (for multi-file policies)
	policySets: #PolicySetConfig
	
	// Validation settings
	validation: {
		// Strict mode fails on any validation error
		strict: bool | *true
		// Validate schemas on load
		validateSchema: bool | *true
		// Maximum policy file size in bytes
		maxFileSize: int | *10485760  // 10MB
	}
}

// NamespaceStrategy defines how namespaces are resolved from file paths.
#NamespaceStrategy: {
	// How to derive namespace from directory structure
	mode: "directory" | "explicit" | "hybrid" | *"hybrid"
	
	// For "directory" mode: which path component is the namespace
	// 0 = root dir, 1 = first subdir, etc.
	// Example: /policies/production/release/policy.cue
	//          depth=0 -> "production", depth=1 -> "release"
	directoryDepth: int | *0
	
	// For "explicit" mode: namespace must be in policy metadata
	// For "hybrid" mode: use metadata if present, else directory
	
	// Default namespace if not determinable
	defaultNamespace: string | *"default"
	
	// Namespace prefix (prepended to all namespaces)
	prefix?: string
}

// ReloadConfig defines hot reload behavior.
#ReloadConfig: {
	// Enable hot reload
	enabled: bool | *true
	
	// Reload strategy
	strategy: #ReloadStrategy
	
	// Debounce period for file system events
	debounce: string | *"500ms"
	
	// Maximum time to wait for reload to complete
	timeout: string | *"30s"
}

// ReloadStrategy defines when policies are reloaded.
#ReloadStrategy: {
	// Watch mode: file system watcher (inotify/fsnotify)
	// Poll mode: periodic directory scanning
	// OnDemand mode: reload only when explicitly triggered or checksum mismatch
	// JIT mode: load policy just-in-time before evaluation
	mode: "watch" | "poll" | "ondemand" | "jit" | *"watch"
	
	// For "poll" mode: how often to check for changes
	pollInterval: string | *"10s"
	
	// For "ondemand" mode: use lock files with checksums
	lockFiles: {
		enabled: bool | *true
		// Lock file extension
		extension: string | *".lock"
		// Checksum algorithm
		algorithm: "sha256" | "xxhash" | *"sha256"
	}
	
	// For "jit" mode: cache loaded policies
	jitCache: {
		enabled: bool | *true
		// TTL for cached policies (0 = check every time)
		ttl: string | *"0s"
	}
}

// PolicySetConfig defines multi-file policy sets.
#PolicySetConfig: {
	// Enable policy sets
	enabled: bool | *true
	
	// Policy set manifest file name
	manifestFile: string | *"policyset.cue"
	
	// Allow policies to import from other files in the set
	allowImports: bool | *true
	
	// Merge strategy for overlapping definitions
	mergeStrategy: "error" | "override" | "merge" | *"error"
}

// EngineConfig defines evaluation engine settings.
#EngineConfig: {
	// CUE context pool size (0 = auto based on CPU)
	contextPoolSize: int | *0
	
	// Maximum worker goroutines for parallel evaluation
	maxWorkers: int | *0  // 0 = NumCPU
	
	// Enable parallel rule evaluation within a policy
	parallelRules: bool | *true
	
	// Result caching
	cache: {
		enabled: bool | *true
		// Maximum cached results
		size: int | *10000
		// Cache TTL
		ttl: string | *"60s"
	}
	
	// Default evaluation timeout
	evaluationTimeout: string | *"30s"
	
	// Fail-fast on first critical violation
	failFast: bool | *false
}

// LoggingConfig defines logging settings.
#LoggingConfig: {
	// Log level: debug, info, warn, error
	level: "debug" | "info" | "warn" | "error" | *"info"
	
	// Log format: json, console
	format: "json" | "console" | *"json"
	
	// Output: stdout, stderr, or file path
	output: string | *"stdout"
	
	// Include caller information
	caller: bool | *false
	
	// Include stack traces for errors
	stacktrace: bool | *false
}

// ObservabilityConfig defines metrics and tracing.
#ObservabilityConfig: {
	// Prometheus metrics
	metrics: {
		enabled: bool | *true
		// Metrics endpoint path
		path: string | *"/metrics"
		// Include Go runtime metrics
		goMetrics: bool | *true
	}
	
	// Distributed tracing (OpenTelemetry)
	tracing: {
		enabled: bool | *false
		// OTLP endpoint
		endpoint?: string
		// Service name
		serviceName: string | *"garmr"
		// Sample rate (0.0 - 1.0)
		sampleRate: float | *0.1
	}
	
	// Health check endpoints
	health: {
		// Liveness probe path
		livenessPath: string | *"/healthz"
		// Readiness probe path
		readinessPath: string | *"/readyz"
	}
}

// Example configurations for common deployment scenarios

// MinimalConfig is a minimal configuration for development.
MinimalConfig: #Config & {
	apiVersion: "config.q.io/v1"
	server: {
		grpc: address: ":9090"
		http: address: ":8080"
	}
	policies: {
		rootDir: "./policies"
		reload: strategy: mode: "watch"
	}
	engine: {}
	logging: level: "debug"
	observability: {}
}

// ContainerConfig is optimized for containerized deployments.
ContainerConfig: #Config & {
	apiVersion: "config.q.io/v1"
	server: {
		grpc: address: ":9090"
		http: address: ":8080"
	}
	policies: {
		rootDir: "/policies"  // Mounted volume
		reload: {
			enabled: true
			strategy: {
				// Use polling in containers (inotify may not work across mounts)
				mode: "poll"
				pollInterval: "5s"
			}
		}
		namespaceStrategy: {
			mode: "hybrid"
			directoryDepth: 0
		}
	}
	engine: {
		contextPoolSize: 0  // Auto-detect
		maxWorkers: 0       // Auto-detect
		cache: {
			enabled: true
			size: 10000
			ttl: "60s"
		}
	}
	logging: {
		level: "info"
		format: "json"
	}
	observability: {
		metrics: enabled: true
		health: {}
	}
}

// HighPerformanceConfig is optimized for high throughput.
HighPerformanceConfig: #Config & {
	apiVersion: "config.q.io/v1"
	server: {
		grpc: {
			address: ":9090"
			maxRecvSize: 33554432  // 32MB
		}
		http: address: ":8080"
	}
	policies: {
		rootDir: "/policies"
		reload: {
			strategy: {
				// JIT for lowest latency on policy updates
				mode: "jit"
				jitCache: {
					enabled: true
					ttl: "5s"
				}
			}
		}
	}
	engine: {
		contextPoolSize: 16  // More contexts for high concurrency
		maxWorkers: 8
		parallelRules: true
		cache: {
			enabled: true
			size: 50000
			ttl: "120s"
		}
	}
	logging: level: "warn"
	observability: {
		metrics: enabled: true
		tracing: {
			enabled: true
			sampleRate: 0.01  // 1% sampling for high volume
		}
	}
}
