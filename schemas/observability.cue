// schemas/observability.cue
// Observability Plugin Schemas
package config

// ============================================
// AUDIT LOGGING (Required - defaults to file)
// ============================================

// FileAuditPluginConfig configures file-based audit logging.
// This is the default audit logger - simple, no external dependencies.
#FileAuditPluginConfig: {
	// Enable audit logging
	enabled: bool | *true
	
	// Path to audit log file
	path: string | *"/var/log/garmr/audit.log"
	
	// Format: jsonl (JSON lines), json, text
	format: "jsonl" | "json" | "text" | *"jsonl"
	
	// Write buffer size (0 = unbuffered)
	bufferSize: int | *4096
	
	// Force sync after each write
	syncOnWrite: bool | *false
	
	// Log rotation settings
	rotation: #FileRotationConfig
	
	// Privacy settings
	privacy: #AuditPrivacyConfig
	
	// Fields to include in audit logs
	includeFields: #AuditIncludeFieldsConfig
}

#FileRotationConfig: {
	enabled: bool | *true
	maxSize: int | *104857600  // 100MB
	maxAge: int | *168         // 7 days in hours
	maxBackups: int | *10
	compress: bool | *true
	rotateOnStartup: bool | *false
}

#AuditPrivacyConfig: {
	// Hash input data instead of storing raw
	hashInput: bool | *false
	
	// Completely exclude input from audit
	excludeInput: bool | *false
	
	// Fields to redact
	redactFields: [...string] | *[]
}

#AuditIncludeFieldsConfig: {
	timestamp: bool | *true
	id: bool | *true
	policy: bool | *true
	namespace: bool | *true
	decision: bool | *true
	violations: bool | *true
	input: bool | *false      // Off by default for privacy
	context: bool | *true
	timing: bool | *true
}

// ============================================
// METRICS (Optional - Q works without this)
// ============================================

// PrometheusPluginConfig configures Prometheus metrics export.
// This is OPTIONAL - Q functions fully without metrics.
#PrometheusPluginConfig: {
	// Enable metrics collection
	enabled: bool | *true
	
	// Address for metrics endpoint
	address: string | *":9090"
	
	// Path for metrics endpoint
	path: string | *"/metrics"
	
	// Metric namespace prefix
	namespace: string | *"q"
	
	// Metric subsystem
	subsystem: string | *"policy"
	
	// Include Go runtime metrics
	enableGoMetrics: bool | *true
	
	// Include process metrics
	enableProcessMetrics: bool | *true
	
	// Histogram buckets for duration metrics
	histogramBuckets: [...float64] | *[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
}

// ============================================
// TRACING (Optional - Q works without this)
// ============================================

// OTelPluginConfig configures OpenTelemetry tracing.
// This is OPTIONAL - Q functions fully without tracing.
#OTelPluginConfig: {
	// Enable tracing
	enabled: bool | *true
	
	// Service name for traces
	serviceName: string | *"garmr"
	
	// Service version
	serviceVersion: string | *"1.0.0"
	
	// Environment (production, staging, etc.)
	environment: string | *"production"
	
	// Exporter configuration
	exporter: #OTelExporterConfig
	
	// Sampling configuration
	sampling: #OTelSamplingConfig
	
	// Context propagators
	propagators: [...string] | *["tracecontext", "baggage"]
}

#OTelExporterConfig: {
	// Exporter type: otlp-grpc, otlp-http
	type: "otlp-grpc" | "otlp-http" | *"otlp-grpc"
	
	// Endpoint for OTLP
	endpoint: string | *"localhost:4317"
	
	// Disable TLS
	insecure: bool | *false
	
	// Headers for authentication
	headers: [string]: string
	
	// Export timeout
	timeout: string | *"10s"
}

#OTelSamplingConfig: {
	// Sampling type: always, never, ratio, parentbased
	type: "always" | "never" | "ratio" | "parentbased" | *"parentbased"
	
	// Sampling ratio (0.0 to 1.0)
	ratio: float64 & >=0 & <=1 | *1.0
}

// ============================================
// LOGGING (Required - defaults to slog/stdout)
// ============================================

// LoggingPluginConfig configures structured logging.
// This is REQUIRED but has sensible defaults (slog to stdout).
#LoggingPluginConfig: {
	// Enable logging
	enabled: bool | *true
	
	// Log level: debug, info, warn, error
	level: "debug" | "info" | "warn" | "error" | *"info"
	
	// Log format: json, text
	format: "json" | "text" | *"json"
	
	// Output destination: stdout, stderr, or file path
	output: string | *"stdout"
	
	// Include source file/line in logs
	addSource: bool | *false
	
	// Timestamp format
	timeFormat: string | *"2006-01-02T15:04:05Z07:00"
	
	// Default fields for all log entries
	defaultFields: [string]: string
	
	// Log rotation settings (for file output)
	rotation: #LogRotationConfig
}

#LogRotationConfig: {
	// Max file size in MB before rotation
	maxSize: int | *100
	
	// Max age in days for old logs
	maxAge: int | *30
	
	// Number of old log files to keep
	maxBackups: int | *5
	
	// Compress rotated files
	compress: bool | *true
}

// ============================================
// KAFKA AUDIT (Optional - enterprise feature)
// ============================================

// KafkaPluginConfig configures Kafka audit logging.
// This is OPTIONAL - use for enterprise/compliance requirements.
// For simple deployments, use audit-file instead.
#KafkaPluginConfig: {
	// Enable audit logging
	enabled: bool | *true
	
	// Kafka broker addresses
	brokers: [...string] | *["localhost:9092"]
	
	// Topic for audit messages
	topic: string | *"q-audit-decisions"
	
	// Client ID
	clientId: string | *"garmr"
	
	// Partitioner: hash, random, roundrobin
	partitioner: "hash" | "random" | "roundrobin" | *"hash"
	
	// Required acknowledgments: none, leader, all
	requiredAcks: "none" | "leader" | "all" | *"leader"
	
	// Compression: none, gzip, snappy, lz4, zstd
	compression: "none" | "gzip" | "snappy" | "lz4" | "zstd" | *"snappy"
	
	// Max retries for failed messages
	maxRetries: int | *3
	
	// Batch size
	batchSize: int | *100
	
	// TLS configuration
	tls: #KafkaTLSConfig
	
	// SASL authentication
	sasl: #KafkaSASLConfig
	
	// Privacy settings
	privacy: #KafkaPrivacyConfig
}

#KafkaTLSConfig: {
	enabled: bool | *false
	certFile: string | *""
	keyFile: string | *""
	caFile: string | *""
	skipVerify: bool | *false
}

#KafkaSASLConfig: {
	enabled: bool | *false
	mechanism: "PLAIN" | "SCRAM-SHA-256" | "SCRAM-SHA-512" | *"PLAIN"
	username: string | *""
	password: string | *""
}

#KafkaPrivacyConfig: {
	// Hash input instead of storing raw values
	hashInput: bool | *true
	
	// Completely exclude input from audit
	excludeInput: bool | *false
	
	// Fields to redact
	redactFields: [...string] | *[]
	
	// Include stack traces for errors
	includeStackTrace: bool | *false
}

// RateLimitConfig configures request rate limiting.
#RateLimitConfig: {
	// Enable rate limiting
	enabled: bool | *true
	
	// Global rate limit (requests per second)
	requestsPerSecond: float64 | *10000
	
	// Burst size
	burst: int | *1000
	
	// Enable per-client rate limiting
	perClient: bool | *true
	
	// Per-client rate limit
	clientRequestsPerSecond: float64 | *1000
	
	// Per-client burst size
	clientBurst: int | *100
	
	// Client identification method: ip, header, cert
	clientIdentifier: "ip" | "header" | "cert" | *"ip"
	
	// Header name for header-based identification
	headerName: string | *"X-Client-ID"
	
	// Cleanup interval for client limiters
	cleanupInterval: string | *"1m"
	
	// TTL for inactive client limiters
	clientTtl: string | *"10m"
	
	// Exempt clients (not rate limited)
	exemptClients: [...string] | *[]
}

// HealthConfig configures health check endpoints.
#HealthConfig: {
	// Enable health endpoints
	enabled: bool | *true
	
	// Address for health endpoints (if separate from main server)
	address: string | *""
	
	// Timeout for health checks
	timeout: string | *"5s"
	
	// Components to check for readiness
	readinessChecks: [...string] | *["storage", "plugins"]
	
	// Components to check for liveness
	livenessChecks: [...string] | *[]
}

// ValidationConfig configures input validation.
#ValidationConfig: {
	// Enable input validation
	enabled: bool | *true
	
	// Reject requests with invalid input
	rejectInvalid: bool | *true
	
	// Include validation errors in response
	includeErrors: bool | *true
	
	// Max input size in bytes
	maxInputSize: int | *1048576  // 1MB
}

// ============================================
// CONFIGURATION EXAMPLES
// ============================================

// Minimal configuration - uses all defaults
// Q works out of the box with this
_minimalConfig: {
	// Uses defaults:
	// - Storage: filesystem (/etc/garmr/policies)
	// - Logging: slog JSON to stdout
	// - Audit: file-based (/var/log/garmr/audit.log)
	// - Metrics: disabled (no-op)
	// - Tracing: disabled (no-op)
}

// Simple deployment - explicit minimal config
_simpleDeploymentConfig: {
	logging: #LoggingPluginConfig & {
		level: "info"
		format: "json"
		output: "stdout"
	}
	
	audit: #FileAuditPluginConfig & {
		enabled: true
		path: "/var/log/garmr/audit.log"
		rotation: {
			enabled: true
			maxSize: 52428800  // 50MB
			maxBackups: 5
		}
	}
	
	// No metrics or tracing - Q works fine without them
}

// Development configuration
_developmentConfig: {
	logging: #LoggingPluginConfig & {
		level: "debug"
		format: "text"  // Human-readable
		output: "stdout"
		addSource: true  // Show file:line
	}
	
	audit: #FileAuditPluginConfig & {
		enabled: true
		path: "./audit.log"
		format: "json"  // Pretty for debugging
		includeFields: {
			input: true  // Include input for debugging
		}
	}
}

// Enterprise deployment - full observability stack
_enterpriseConfig: {
	prometheus: #PrometheusPluginConfig & {
		address: ":9090"
		enableGoMetrics: true
	}
	
	otel: #OTelPluginConfig & {
		serviceName: "garmr"
		environment: "production"
		exporter: {
			type: "otlp-grpc"
			endpoint: "otel-collector:4317"
		}
		sampling: {
			type: "parentbased"
			ratio: 0.1  // Sample 10% in production
		}
	}
	
	logging: #LoggingPluginConfig & {
		level: "info"
		format: "json"
		output: "stdout"
		defaultFields: {
			service: "garmr"
			version: "1.0.0"
		}
	}
	
	kafka: #KafkaPluginConfig & {
		brokers: ["kafka-1:9092", "kafka-2:9092", "kafka-3:9092"]
		topic: "policy-audit-decisions"
		tls: enabled: true
		sasl: {
			enabled: true
			mechanism: "SCRAM-SHA-512"
		}
		privacy: {
			hashInput: true
		}
	}
	
	rateLimit: #RateLimitConfig & {
		requestsPerSecond: 50000
		perClient: true
		clientRequestsPerSecond: 5000
	}
	
	health: #HealthConfig & {
		readinessChecks: ["storage", "plugins", "kafka"]
	}
}
