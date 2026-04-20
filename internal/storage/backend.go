// internal/storage/backend.go
// Package storage provides a unified interface for policy storage backends.
// The engine interacts only with this interface, remaining agnostic to
// whether policies are stored on local disk, S3, NFS, or other backends.
package storage

import (
	"context"
	"io"
	"time"
)

// Backend defines the interface for policy storage.
// All storage implementations (filesystem, S3, etc.) implement this interface.
type Backend interface {
	// Type returns the backend type identifier (e.g., "filesystem", "s3").
	Type() string

	// List returns all policy files matching the given pattern.
	// Pattern uses glob syntax (e.g., "**/*.cue").
	List(ctx context.Context, pattern string) ([]FileInfo, error)

	// Get retrieves the content of a file.
	Get(ctx context.Context, path string) ([]byte, error)

	// GetReader returns a reader for streaming large files.
	GetReader(ctx context.Context, path string) (io.ReadCloser, error)

	// Stat returns file metadata without reading content.
	Stat(ctx context.Context, path string) (*FileInfo, error)

	// Watch returns a channel that receives events when files change.
	// Returns nil if the backend doesn't support watching.
	Watch(ctx context.Context, pattern string) (<-chan Event, error)

	// Checksum returns the checksum of a file (for change detection).
	// Backends may compute this differently (ETag, MD5, SHA256).
	Checksum(ctx context.Context, path string) (string, error)

	// Close releases any resources held by the backend.
	Close() error
}

// FileInfo contains metadata about a file.
type FileInfo struct {
	// Path relative to the storage root
	Path string

	// Size in bytes
	Size int64

	// Last modification time
	ModTime time.Time

	// Checksum/ETag (backend-specific)
	Checksum string

	// IsDir indicates if this is a directory
	IsDir bool

	// Metadata contains backend-specific metadata
	Metadata map[string]string
}

// Event represents a file change event.
type Event struct {
	// Type of event
	Type EventType

	// Path of the affected file
	Path string

	// Timestamp of the event
	Timestamp time.Time

	// Error if the event represents an error condition
	Error error
}

// EventType defines the type of file event.
type EventType int

const (
	EventCreate EventType = iota
	EventModify
	EventDelete
	EventError
)

func (e EventType) String() string {
	switch e {
	case EventCreate:
		return "create"
	case EventModify:
		return "modify"
	case EventDelete:
		return "delete"
	case EventError:
		return "error"
	default:
		return "unknown"
	}
}

// Config is the base configuration for all backends.
type Config struct {
	// Type of backend: "filesystem", "s3", "gcs", "azure"
	Type string `json:"type"`

	// Root path/prefix for policies
	Root string `json:"root"`

	// Include patterns (glob)
	IncludePatterns []string `json:"includePatterns,omitempty"`

	// Exclude patterns (glob)
	ExcludePatterns []string `json:"excludePatterns,omitempty"`

	// Backend-specific options
	Options map[string]interface{} `json:"options,omitempty"`
}

// Registry holds registered backend factories.
type Registry struct {
	factories map[string]Factory
}

// Factory creates a Backend from configuration.
type Factory func(cfg Config) (Backend, error)

// NewRegistry creates a new backend registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
	}
}

// Register adds a backend factory to the registry.
func (r *Registry) Register(backendType string, factory Factory) {
	r.factories[backendType] = factory
}

// Create instantiates a backend from configuration.
func (r *Registry) Create(cfg Config) (Backend, error) {
	factory, ok := r.factories[cfg.Type]
	if !ok {
		return nil, &ErrUnknownBackend{Type: cfg.Type}
	}
	return factory(cfg)
}

// DefaultRegistry is the global backend registry.
var DefaultRegistry = NewRegistry()

// Register adds a backend to the default registry.
func Register(backendType string, factory Factory) {
	DefaultRegistry.Register(backendType, factory)
}

// New creates a backend using the default registry.
func New(cfg Config) (Backend, error) {
	return DefaultRegistry.Create(cfg)
}

// Errors

// ErrUnknownBackend is returned when a backend type is not registered.
type ErrUnknownBackend struct {
	Type string
}

func (e *ErrUnknownBackend) Error() string {
	return "unknown storage backend: " + e.Type
}

// ErrNotFound is returned when a file doesn't exist.
type ErrNotFound struct {
	Path string
}

func (e *ErrNotFound) Error() string {
	return "file not found: " + e.Path
}

// ErrAccessDenied is returned when access to a file is denied.
type ErrAccessDenied struct {
	Path   string
	Reason string
}

func (e *ErrAccessDenied) Error() string {
	return "access denied: " + e.Path + ": " + e.Reason
}
