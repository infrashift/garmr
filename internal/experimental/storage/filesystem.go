// internal/storage/filesystem.go
// Package storage provides storage backend implementations.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

func init() {
	Register("filesystem", NewFilesystemBackend)
	Register("file", NewFilesystemBackend) // Alias
	Register("fs", NewFilesystemBackend)   // Alias
}

// FilesystemBackend implements Backend for local filesystem storage.
type FilesystemBackend struct {
	root     string
	includes []string
	excludes []string

	watcherMu sync.Mutex
	watcher   *fsnotify.Watcher
	watching  bool
}

// FilesystemOptions contains filesystem-specific options.
type FilesystemOptions struct {
	// FollowSymlinks determines whether to follow symbolic links
	FollowSymlinks bool `json:"followSymlinks"`
}

// NewFilesystemBackend creates a new filesystem backend.
func NewFilesystemBackend(cfg Config) (Backend, error) {
	root := cfg.Root
	if root == "" {
		root = "/policies"
	}

	// Ensure root exists
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, &ErrNotFound{Path: root}
	}

	includes := cfg.IncludePatterns
	if len(includes) == 0 {
		includes = []string{"**/*.cue"}
	}

	excludes := cfg.ExcludePatterns
	if len(excludes) == 0 {
		excludes = []string{"**/*_test.cue", "**/testdata/**"}
	}

	return &FilesystemBackend{
		root:     root,
		includes: includes,
		excludes: excludes,
	}, nil
}

func (b *FilesystemBackend) Type() string {
	return "filesystem"
}

func (b *FilesystemBackend) List(ctx context.Context, pattern string) ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.WalkDir(b.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(b.root, path)
		if err != nil {
			return err
		}

		// Apply pattern matching
		if !b.matchesPatterns(relPath) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		files = append(files, FileInfo{
			Path:    relPath,
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsDir:   false,
		})

		return nil
	})

	return files, err
}

func (b *FilesystemBackend) Get(ctx context.Context, path string) ([]byte, error) {
	fullPath := filepath.Join(b.root, path)

	// Security: ensure path doesn't escape root
	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(b.root)) {
		return nil, &ErrAccessDenied{Path: path, Reason: "path traversal attempt"}
	}

	content, err := os.ReadFile(fullPath)
	if os.IsNotExist(err) {
		return nil, &ErrNotFound{Path: path}
	}
	if os.IsPermission(err) {
		return nil, &ErrAccessDenied{Path: path, Reason: "permission denied"}
	}
	return content, err
}

func (b *FilesystemBackend) GetReader(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath := filepath.Join(b.root, path)

	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(b.root)) {
		return nil, &ErrAccessDenied{Path: path, Reason: "path traversal attempt"}
	}

	f, err := os.Open(fullPath)
	if os.IsNotExist(err) {
		return nil, &ErrNotFound{Path: path}
	}
	if os.IsPermission(err) {
		return nil, &ErrAccessDenied{Path: path, Reason: "permission denied"}
	}
	return f, err
}

func (b *FilesystemBackend) Stat(ctx context.Context, path string) (*FileInfo, error) {
	fullPath := filepath.Join(b.root, path)

	if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(b.root)) {
		return nil, &ErrAccessDenied{Path: path, Reason: "path traversal attempt"}
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		return nil, &ErrNotFound{Path: path}
	}
	if err != nil {
		return nil, err
	}

	return &FileInfo{
		Path:    path,
		Size:    info.Size(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
	}, nil
}

func (b *FilesystemBackend) Checksum(ctx context.Context, path string) (string, error) {
	content, err := b.Get(ctx, path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func (b *FilesystemBackend) Watch(ctx context.Context, pattern string) (<-chan Event, error) {
	b.watcherMu.Lock()
	defer b.watcherMu.Unlock()

	if b.watching {
		return nil, nil // Already watching
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	b.watcher = watcher

	// Add root directory and subdirectories
	err = filepath.WalkDir(b.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
	if err != nil {
		watcher.Close()
		return nil, err
	}

	events := make(chan Event, 100)
	b.watching = true

	go b.watchLoop(ctx, watcher, events)

	return events, nil
}

func (b *FilesystemBackend) watchLoop(ctx context.Context, watcher *fsnotify.Watcher, events chan<- Event) {
	defer close(events)
	defer watcher.Close()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			relPath, err := filepath.Rel(b.root, event.Name)
			if err != nil {
				continue
			}

			if !b.matchesPatterns(relPath) {
				continue
			}

			var eventType EventType
			switch {
			case event.Op&fsnotify.Create == fsnotify.Create:
				eventType = EventCreate
			case event.Op&fsnotify.Write == fsnotify.Write:
				eventType = EventModify
			case event.Op&fsnotify.Remove == fsnotify.Remove:
				eventType = EventDelete
			case event.Op&fsnotify.Rename == fsnotify.Rename:
				eventType = EventDelete
			default:
				continue
			}

			select {
			case events <- Event{Type: eventType, Path: relPath}:
			default:
				// Channel full, skip event
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			select {
			case events <- Event{Type: EventError, Error: err}:
			default:
			}
		}
	}
}

func (b *FilesystemBackend) Close() error {
	b.watcherMu.Lock()
	defer b.watcherMu.Unlock()

	if b.watcher != nil {
		b.watching = false
		return b.watcher.Close()
	}
	return nil
}

func (b *FilesystemBackend) matchesPatterns(path string) bool {
	// Check excludes first
	for _, pattern := range b.excludes {
		if matchGlobPattern(pattern, path) {
			return false
		}
	}

	// Check includes
	for _, pattern := range b.includes {
		if matchGlobPattern(pattern, path) {
			return true
		}
	}

	return false
}

func matchGlobPattern(pattern, path string) bool {
	// Handle ** (match any depth)
	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			hasPrefix := prefix == "" || strings.HasPrefix(path, prefix)
			hasSuffix := suffix == "" || strings.HasSuffix(path, suffix)

			return hasPrefix && hasSuffix
		}
	}

	// Standard glob matching
	matched, _ := filepath.Match(pattern, path)
	return matched
}
