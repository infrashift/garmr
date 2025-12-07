// schemas/storage.cue
// Storage Backend Configuration Schema
// Defines configuration for all supported storage backends
package config

// StorageConfig defines how Q accesses policy files.
// The engine is storage-agnostic - it only sees the Backend interface.
#StorageConfig: {
	// Backend type: "filesystem", "s3", "minio", "gcs", "azure"
	type: #StorageType
	
	// Root path/prefix for policies
	root: string | *"/policies"
	
	// Include patterns (glob syntax)
	includePatterns: [...string] | *["**/*.cue"]
	
	// Exclude patterns
	excludePatterns: [...string] | *["**/*_test.cue", "**/testdata/**"]
	
	// Backend-specific options
	options: #StorageOptions
}

#StorageType: "filesystem" | "file" | "fs" | "s3" | "minio" | "gcs" | "azure"

// StorageOptions is a union of all backend-specific options
#StorageOptions: #FilesystemOptions | #S3Options | #GCSOptions | #AzureOptions

// ============================================
// FILESYSTEM BACKEND
// ============================================

#FilesystemOptions: {
	// Follow symbolic links
	followSymlinks: bool | *false
}

// ============================================
// S3 / MINIO BACKEND
// ============================================

#S3Options: {
	// S3-compatible endpoint (leave empty for AWS S3)
	// Examples:
	//   AWS S3:     "" (uses s3.amazonaws.com)
	//   MinIO:      "minio.example.com:9000"
	//   Localstack: "localhost:4566"
	endpoint: string | *""
	
	// AWS region
	region: string | *"us-east-1"
	
	// Bucket name (required)
	bucket: string
	
	// Authentication (leave empty to use IAM roles / environment)
	accessKeyId:     string | *""
	secretAccessKey: string | *""
	sessionToken:    string | *""
	
	// Use HTTPS
	useSsl: bool | *true
	
	// Polling interval for change detection
	// S3 doesn't support native file watching, so we poll
	pollInterval: string | *"10s"
	
	// Use SHA256 checksums instead of ETags
	// ETags are faster but may not be consistent for multipart uploads
	useSha256Checksum: bool | *false
}

// ============================================
// GCS BACKEND (Future)
// ============================================

#GCSOptions: {
	// GCS bucket name
	bucket: string
	
	// Project ID
	project: string | *""
	
	// Path to service account key file (optional, uses ADC if not set)
	credentialsFile: string | *""
	
	// Polling interval
	pollInterval: string | *"10s"
}

// ============================================
// AZURE BLOB BACKEND (Future)
// ============================================

#AzureOptions: {
	// Storage account name
	accountName: string
	
	// Container name
	container: string
	
	// Account key or connection string
	accountKey:       string | *""
	connectionString: string | *""
	
	// Use managed identity
	useManagedIdentity: bool | *false
	
	// Polling interval
	pollInterval: string | *"10s"
}

// ============================================
// EXAMPLE CONFIGURATIONS
// ============================================

// Local filesystem (simplest)
_exampleFilesystem: #StorageConfig & {
	type: "filesystem"
	root: "/policies"
	options: #FilesystemOptions & {
		followSymlinks: false
	}
}

// Container with mounted volume
_exampleContainerMount: #StorageConfig & {
	type: "filesystem"
	root: "/mnt/policies"  // Mounted from host or PVC
	options: #FilesystemOptions & {}
}

// MinIO (self-hosted S3-compatible)
_exampleMinIO: #StorageConfig & {
	type: "minio"
	root: "policies/"  // Prefix in bucket
	options: #S3Options & {
		endpoint:        "minio.storage.svc.cluster.local:9000"
		bucket:          "q-policies"
		accessKeyId:     "${MINIO_ACCESS_KEY}"      // From environment
		secretAccessKey: "${MINIO_SECRET_KEY}"
		useSsl:          false                       // Internal cluster
		pollInterval:    "5s"
	}
}

// AWS S3
_exampleAWSS3: #StorageConfig & {
	type: "s3"
	root: "policies/production/"
	options: #S3Options & {
		// No endpoint = AWS S3
		region:       "us-west-2"
		bucket:       "my-company-policies"
		// No credentials = use IAM role (recommended)
		useSsl:       true
		pollInterval: "30s"
	}
}

// AWS S3 with explicit credentials (for local dev)
_exampleAWSS3WithCreds: #StorageConfig & {
	type: "s3"
	root: "dev/policies/"
	options: #S3Options & {
		region:          "us-east-1"
		bucket:          "dev-policies"
		accessKeyId:     "${AWS_ACCESS_KEY_ID}"
		secretAccessKey: "${AWS_SECRET_ACCESS_KEY}"
		pollInterval:    "10s"
	}
}

// ============================================
// FULL CONFIG EXAMPLE WITH STORAGE
// ============================================

// Updated Config with storage backend
#ConfigWithStorage: {
	apiVersion: "config.q.io/v1"
	
	server: #ServerConfig
	
	// Storage replaces the simple policies.rootDir
	storage: #StorageConfig
	
	// Policy loading behavior (works with any backend)
	policies: {
		// Namespace resolution
		namespaceStrategy: #NamespaceStrategy
		
		// Hot reload
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
	
	engine: #EngineConfig
	logging: #LoggingConfig
	observability: #ObservabilityConfig
}

// Production config using MinIO
ProductionMinIOConfig: #ConfigWithStorage & {
	apiVersion: "config.q.io/v1"
	
	server: {
		grpc: address: ":9090"
		http: address: ":8080"
	}
	
	storage: {
		type: "minio"
		root: "policies/"
		options: #S3Options & {
			endpoint:        "minio.storage.svc.cluster.local:9000"
			bucket:          "q-policies"
			accessKeyId:     "${MINIO_ACCESS_KEY}"
			secretAccessKey: "${MINIO_SECRET_KEY}"
			useSsl:          false
			pollInterval:    "5s"
		}
	}
	
	policies: {
		namespaceStrategy: {
			mode:           "hybrid"
			directoryDepth: 0
		}
		reload: {
			enabled: true
			// Storage backend handles change detection via polling
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
