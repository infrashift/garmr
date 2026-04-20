// internal/storage/s3.go
// Package storage provides storage backend implementations.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func init() {
	Register("s3", NewS3Backend)
	Register("minio", NewS3Backend) // Alias
}

// S3Backend implements Backend for S3-compatible storage (AWS S3, MinIO, etc.).
type S3Backend struct {
	client   *minio.Client
	bucket   string
	prefix   string
	includes []string
	excludes []string

	// Polling for change detection (S3 doesn't support native watching)
	pollInterval time.Duration
	stopPolling  chan struct{}
	pollingMu    sync.Mutex
	polling      bool

	// Cache for change detection
	cacheMu    sync.RWMutex
	etags      map[string]string // path -> etag
	lastPolled time.Time
}

// S3Options contains S3-specific configuration.
type S3Options struct {
	// Endpoint for S3-compatible service (e.g., "minio.example.com:9000")
	// Leave empty for AWS S3.
	Endpoint string `json:"endpoint"`

	// Region (e.g., "us-east-1")
	Region string `json:"region"`

	// Bucket name
	Bucket string `json:"bucket"`

	// AccessKeyID for authentication
	AccessKeyID string `json:"accessKeyId"`

	// SecretAccessKey for authentication
	SecretAccessKey string `json:"secretAccessKey"`

	// UseSSL determines whether to use HTTPS
	UseSSL bool `json:"useSsl"`

	// PollInterval for change detection (default: 10s)
	PollInterval string `json:"pollInterval"`

	// SessionToken for temporary credentials (optional)
	SessionToken string `json:"sessionToken"`
}

// NewS3Backend creates a new S3/MinIO backend.
func NewS3Backend(cfg Config) (Backend, error) {
	opts := S3Options{
		Region:       "us-east-1",
		UseSSL:       true,
		PollInterval: "10s",
	}

	// Parse options from config
	if v, ok := cfg.Options["endpoint"].(string); ok {
		opts.Endpoint = v
	}
	if v, ok := cfg.Options["region"].(string); ok {
		opts.Region = v
	}
	if v, ok := cfg.Options["bucket"].(string); ok {
		opts.Bucket = v
	}
	if v, ok := cfg.Options["accessKeyId"].(string); ok {
		opts.AccessKeyID = v
	}
	if v, ok := cfg.Options["secretAccessKey"].(string); ok {
		opts.SecretAccessKey = v
	}
	if v, ok := cfg.Options["useSsl"].(bool); ok {
		opts.UseSSL = v
	}
	if v, ok := cfg.Options["pollInterval"].(string); ok {
		opts.PollInterval = v
	}
	if v, ok := cfg.Options["sessionToken"].(string); ok {
		opts.SessionToken = v
	}

	if opts.Bucket == "" {
		return nil, fmt.Errorf("s3: bucket is required")
	}

	// Determine endpoint
	endpoint := opts.Endpoint
	if endpoint == "" {
		// Default to AWS S3
		endpoint = "s3.amazonaws.com"
	}

	// Create MinIO client (compatible with AWS S3)
	var creds *credentials.Credentials
	if opts.AccessKeyID != "" {
		creds = credentials.NewStaticV4(opts.AccessKeyID, opts.SecretAccessKey, opts.SessionToken)
	} else {
		// Use IAM role / environment credentials
		creds = credentials.NewIAM("")
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  creds,
		Secure: opts.UseSSL,
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: creating client: %w", err)
	}

	pollInterval, err := time.ParseDuration(opts.PollInterval)
	if err != nil {
		pollInterval = 10 * time.Second
	}

	includes := cfg.IncludePatterns
	if len(includes) == 0 {
		includes = []string{"**/*.cue"}
	}

	excludes := cfg.ExcludePatterns
	if len(excludes) == 0 {
		excludes = []string{"**/*_test.cue", "**/testdata/**"}
	}

	prefix := cfg.Root
	// Normalize prefix (no leading slash, trailing slash)
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}

	return &S3Backend{
		client:       client,
		bucket:       opts.Bucket,
		prefix:       prefix,
		includes:     includes,
		excludes:     excludes,
		pollInterval: pollInterval,
		etags:        make(map[string]string),
	}, nil
}

func (b *S3Backend) Type() string {
	return "s3"
}

func (b *S3Backend) List(ctx context.Context, pattern string) ([]FileInfo, error) {
	var files []FileInfo

	objectCh := b.client.ListObjects(ctx, b.bucket, minio.ListObjectsOptions{
		Prefix:    b.prefix,
		Recursive: true,
	})

	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("s3: listing objects: %w", object.Err)
		}

		// Get relative path (remove prefix)
		relPath := strings.TrimPrefix(object.Key, b.prefix)
		if relPath == "" {
			continue
		}

		// Apply pattern matching
		if !b.matchesPatterns(relPath) {
			continue
		}

		files = append(files, FileInfo{
			Path:     relPath,
			Size:     object.Size,
			ModTime:  object.LastModified,
			Checksum: object.ETag,
			IsDir:    false,
			Metadata: map[string]string{
				"etag":         object.ETag,
				"storageClass": object.StorageClass,
			},
		})
	}

	return files, nil
}

func (b *S3Backend) Get(ctx context.Context, filePath string) ([]byte, error) {
	objectPath := b.prefix + filePath

	object, err := b.client.GetObject(ctx, b.bucket, objectPath, minio.GetObjectOptions{})
	if err != nil {
		return nil, b.translateError(err, filePath)
	}
	defer object.Close()

	content, err := io.ReadAll(object)
	if err != nil {
		return nil, b.translateError(err, filePath)
	}

	return content, nil
}

func (b *S3Backend) GetReader(ctx context.Context, filePath string) (io.ReadCloser, error) {
	objectPath := b.prefix + filePath

	object, err := b.client.GetObject(ctx, b.bucket, objectPath, minio.GetObjectOptions{})
	if err != nil {
		return nil, b.translateError(err, filePath)
	}

	return object, nil
}

func (b *S3Backend) Stat(ctx context.Context, filePath string) (*FileInfo, error) {
	objectPath := b.prefix + filePath

	info, err := b.client.StatObject(ctx, b.bucket, objectPath, minio.StatObjectOptions{})
	if err != nil {
		return nil, b.translateError(err, filePath)
	}

	return &FileInfo{
		Path:     filePath,
		Size:     info.Size,
		ModTime:  info.LastModified,
		Checksum: info.ETag,
		IsDir:    false,
		Metadata: map[string]string{
			"etag":         info.ETag,
			"contentType":  info.ContentType,
			"storageClass": info.StorageClass,
		},
	}, nil
}

func (b *S3Backend) Checksum(ctx context.Context, filePath string) (string, error) {
	// Try to use ETag first (efficient for S3)
	info, err := b.Stat(ctx, filePath)
	if err != nil {
		return "", err
	}

	// ETag for non-multipart uploads is MD5
	// For consistency, we could compute SHA256, but that requires downloading
	// Using ETag is more efficient for change detection
	return "etag:" + info.Checksum, nil
}

// Watch implements change detection via polling (S3 doesn't support native watching).
func (b *S3Backend) Watch(ctx context.Context, pattern string) (<-chan Event, error) {
	b.pollingMu.Lock()
	defer b.pollingMu.Unlock()

	if b.polling {
		return nil, nil // Already polling
	}

	events := make(chan Event, 100)
	b.stopPolling = make(chan struct{})
	b.polling = true

	go b.pollLoop(ctx, events)

	return events, nil
}

func (b *S3Backend) pollLoop(ctx context.Context, events chan<- Event) {
	defer close(events)

	ticker := time.NewTicker(b.pollInterval)
	defer ticker.Stop()

	// Initial scan to populate cache
	b.scanForChanges(ctx, events, true)

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopPolling:
			return
		case <-ticker.C:
			b.scanForChanges(ctx, events, false)
		}
	}
}

func (b *S3Backend) scanForChanges(ctx context.Context, events chan<- Event, initial bool) {
	files, err := b.List(ctx, "")
	if err != nil {
		select {
		case events <- Event{Type: EventError, Error: err}:
		default:
		}
		return
	}

	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()

	currentFiles := make(map[string]string)

	for _, file := range files {
		currentFiles[file.Path] = file.Checksum

		oldEtag, existed := b.etags[file.Path]

		if !existed {
			b.etags[file.Path] = file.Checksum
			if !initial {
				select {
				case events <- Event{Type: EventCreate, Path: file.Path, Timestamp: time.Now()}:
				default:
				}
			}
		} else if oldEtag != file.Checksum {
			b.etags[file.Path] = file.Checksum
			select {
			case events <- Event{Type: EventModify, Path: file.Path, Timestamp: time.Now()}:
			default:
			}
		}
	}

	// Check for deleted files
	for filePath := range b.etags {
		if _, exists := currentFiles[filePath]; !exists {
			delete(b.etags, filePath)
			if !initial {
				select {
				case events <- Event{Type: EventDelete, Path: filePath, Timestamp: time.Now()}:
				default:
				}
			}
		}
	}

	b.lastPolled = time.Now()
}

func (b *S3Backend) Close() error {
	b.pollingMu.Lock()
	defer b.pollingMu.Unlock()

	if b.polling {
		close(b.stopPolling)
		b.polling = false
	}

	return nil
}

func (b *S3Backend) translateError(err error, filePath string) error {
	errResp := minio.ToErrorResponse(err)
	switch errResp.Code {
	case "NoSuchKey":
		return &ErrNotFound{Path: filePath}
	case "AccessDenied":
		return &ErrAccessDenied{Path: filePath, Reason: errResp.Message}
	default:
		return fmt.Errorf("s3: %s: %w", filePath, err)
	}
}

func (b *S3Backend) matchesPatterns(filePath string) bool {
	for _, pattern := range b.excludes {
		if matchS3Pattern(pattern, filePath) {
			return false
		}
	}

	for _, pattern := range b.includes {
		if matchS3Pattern(pattern, filePath) {
			return true
		}
	}

	return false
}

func matchS3Pattern(pattern, filePath string) bool {
	// Handle ** (match any depth)
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")

		// Handle patterns like **/testdata/** (directory-in-path match)
		if len(parts) == 3 && parts[0] == "" && parts[2] == "" {
			mid := strings.Trim(parts[1], "/")
			return strings.Contains(filePath, mid+"/") || strings.HasPrefix(filePath, mid+"/")
		}

		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			hasPrefix := prefix == "" || strings.HasPrefix(filePath, prefix+"/") || filePath == prefix

			var hasSuffix bool
			if suffix == "" {
				hasSuffix = true
			} else if !strings.Contains(suffix, "/") {
				// Simple glob suffix like *.cue — match against filename
				hasSuffix, _ = path.Match(suffix, path.Base(filePath))
			} else {
				hasSuffix = strings.HasSuffix(filePath, suffix)
			}

			return hasPrefix && hasSuffix
		}
	}

	// Standard glob matching
	matched, _ := path.Match(pattern, filePath)
	return matched
}

// S3BackendWithSHA256 wraps S3Backend to compute SHA256 checksums.
// Use when you need consistent checksums across storage backends.
type S3BackendWithSHA256 struct {
	*S3Backend
}

// NewS3BackendWithSHA256 creates an S3 backend that computes SHA256 checksums.
func NewS3BackendWithSHA256(cfg Config) (Backend, error) {
	base, err := NewS3Backend(cfg)
	if err != nil {
		return nil, err
	}
	return &S3BackendWithSHA256{S3Backend: base.(*S3Backend)}, nil
}

func (b *S3BackendWithSHA256) Checksum(ctx context.Context, filePath string) (string, error) {
	content, err := b.Get(ctx, filePath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// S3EventBridgeWatcher provides real-time notifications via S3 Event Notifications.
// This requires configuring S3 bucket notifications to an SQS queue or similar.
// Implementation left as extension point.
type S3EventBridgeWatcher struct {
	// SQS queue URL or SNS topic ARN
	NotificationEndpoint string

	// Implementation would poll SQS or subscribe to SNS
}

// Compile-time check that S3Backend implements Backend
var _ Backend = (*S3Backend)(nil)
var _ Backend = (*S3BackendWithSHA256)(nil)
