// internal/loader/backend_loader.go
// Package loader handles policy loading using pluggable storage backends.
// The loader is decoupled from storage implementation details.
package loader

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/storage"
)

// ReloadMode defines when policies are reloaded.
type ReloadMode string

const (
	ReloadWatch    ReloadMode = "watch"    // Storage backend watcher
	ReloadPoll     ReloadMode = "poll"     // Periodic polling
	ReloadOnDemand ReloadMode = "ondemand" // Lock file based
	ReloadJIT      ReloadMode = "jit"      // Just-in-time before eval
)

// PolicyFile represents a loaded policy file.
type PolicyFile struct {
	Path      string
	Namespace string
	Name      string
	Content   []byte
	Checksum  string
	ModTime   time.Time
	SetName   string // If part of a policy set
}

// Loader loads policies from a storage backend.
// It handles hot reload, namespace resolution, and policy sets,
// while remaining agnostic to the underlying storage mechanism.
type Loader struct {
	backend storage.Backend
	config  Config
	logger  *zap.Logger

	mu        sync.RWMutex
	files     map[string]*PolicyFile
	checksums map[string]string

	// Callbacks
	onLoad   func([]PolicyFile) error
	onReload func([]PolicyFile) error
	onError  func(error)

	// State
	running bool
	stopCh  chan struct{}

	// Metrics
	loadCount   int64
	reloadCount int64
	errorCount  int64
}

// Config configures the loader behavior.
// Storage configuration is separate (in storage.Config).
type Config struct {
	// Namespace resolution strategy
	NamespaceStrategy NamespaceStrategy

	// Hot reload behavior
	ReloadMode   ReloadMode
	Debounce     time.Duration
	PollInterval time.Duration

	// Lock file settings (for on-demand mode)
	LockFileExtension string

	// Policy sets
	EnablePolicySets bool
	ManifestFile     string

	// Validation
	Strict      bool
	MaxFileSize int64
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		NamespaceStrategy: NamespaceStrategy{
			Mode:    "hybrid",
			Depth:   0,
			Default: "default",
		},
		ReloadMode:        ReloadWatch,
		Debounce:          500 * time.Millisecond,
		PollInterval:      10 * time.Second,
		LockFileExtension: ".lock",
		EnablePolicySets:  true,
		ManifestFile:      "policyset.cue",
		Strict:            true,
		MaxFileSize:       10 * 1024 * 1024,
	}
}

// NamespaceStrategy defines how namespaces are derived from paths.
type NamespaceStrategy struct {
	Mode    string // "directory", "explicit", "hybrid"
	Depth   int    // Directory depth for namespace
	Default string // Default namespace
	Prefix  string // Prefix to add to all namespaces
}

// NewLoader creates a new policy loader.
func NewLoader(backend storage.Backend, cfg Config, logger *zap.Logger) *Loader {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Loader{
		backend:   backend,
		config:    cfg,
		logger:    logger,
		files:     make(map[string]*PolicyFile),
		checksums: make(map[string]string),
		stopCh:    make(chan struct{}),
	}
}

// OnLoad sets a callback invoked when policies are initially loaded.
func (l *Loader) OnLoad(fn func([]PolicyFile) error) {
	l.onLoad = fn
}

// OnReload sets a callback invoked when policies are reloaded.
func (l *Loader) OnReload(fn func([]PolicyFile) error) {
	l.onReload = fn
}

// OnError sets a callback invoked when errors occur.
func (l *Loader) OnError(fn func(error)) {
	l.onError = fn
}

// Start begins loading and watching for policy changes.
func (l *Loader) Start(ctx context.Context) error {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return nil
	}
	l.running = true
	l.mu.Unlock()

	// Initial load
	files, err := l.loadAll(ctx)
	if err != nil {
		return fmt.Errorf("initial load: %w", err)
	}

	// Notify callback
	if l.onLoad != nil {
		if err := l.onLoad(files); err != nil {
			return fmt.Errorf("load callback: %w", err)
		}
	}

	l.logger.Info("policies loaded",
		zap.String("backend", l.backend.Type()),
		zap.Int("count", len(files)),
	)

	// Start watching based on reload mode
	switch l.config.ReloadMode {
	case ReloadWatch:
		return l.startWatching(ctx)
	case ReloadPoll:
		return l.startPolling(ctx)
	case ReloadOnDemand, ReloadJIT:
		// No background process needed
		return nil
	}

	return nil
}

// Stop stops the loader.
func (l *Loader) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	close(l.stopCh)
	l.running = false

	return l.backend.Close()
}

// loadAll loads all policy files from the storage backend.
func (l *Loader) loadAll(ctx context.Context) ([]PolicyFile, error) {
	// List all files from backend
	infos, err := l.backend.List(ctx, "**/*.cue")
	if err != nil {
		return nil, err
	}

	var files []PolicyFile

	for _, info := range infos {
		// Skip lock files
		if strings.HasSuffix(info.Path, l.config.LockFileExtension) {
			continue
		}

		// Skip files exceeding max size
		if info.Size > l.config.MaxFileSize {
			l.logger.Warn("skipping large file",
				zap.String("path", info.Path),
				zap.Int64("size", info.Size),
			)
			continue
		}

		// Load file content
		content, err := l.backend.Get(ctx, info.Path)
		if err != nil {
			if l.config.Strict {
				return nil, fmt.Errorf("loading %s: %w", info.Path, err)
			}
			l.logger.Warn("failed to load file", zap.String("path", info.Path), zap.Error(err))
			continue
		}

		// Get checksum
		checksum := info.Checksum
		if checksum == "" {
			checksum, _ = l.backend.Checksum(ctx, info.Path)
		}

		// Derive namespace and name
		namespace, name := l.deriveNamespaceName(info.Path)

		file := PolicyFile{
			Path:      info.Path,
			Namespace: namespace,
			Name:      name,
			Content:   content,
			Checksum:  checksum,
			ModTime:   info.ModTime,
		}

		files = append(files, file)

		// Update cache
		l.mu.Lock()
		l.files[info.Path] = &file
		l.checksums[info.Path] = checksum
		l.mu.Unlock()
	}

	l.loadCount++
	return files, nil
}

// startWatching uses the backend's Watch capability.
func (l *Loader) startWatching(ctx context.Context) error {
	events, err := l.backend.Watch(ctx, "**/*.cue")
	if err != nil {
		return err
	}

	if events == nil {
		// Backend doesn't support watching, fall back to polling
		l.logger.Info("backend doesn't support watching, using polling",
			zap.String("backend", l.backend.Type()),
		)
		return l.startPolling(ctx)
	}

	go l.handleEvents(ctx, events)
	return nil
}

// handleEvents processes file change events from the backend.
func (l *Loader) handleEvents(ctx context.Context, events <-chan storage.Event) {
	// Debounce: collect events and process in batches
	var pending []storage.Event
	var timer *time.Timer

	processEvents := func() {
		if len(pending) == 0 {
			return
		}

		// Deduplicate paths
		paths := make(map[string]storage.EventType)
		for _, e := range pending {
			paths[e.Path] = e.Type
		}
		pending = nil

		l.processChangedFiles(ctx, paths)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return

		case event, ok := <-events:
			if !ok {
				return
			}

			if event.Type == storage.EventError {
				if l.onError != nil {
					l.onError(event.Error)
				}
				continue
			}

			// Skip lock files
			if strings.HasSuffix(event.Path, l.config.LockFileExtension) {
				continue
			}

			pending = append(pending, event)

			// Reset debounce timer
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(l.config.Debounce, processEvents)
		}
	}
}

// startPolling periodically checks for changes.
func (l *Loader) startPolling(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(l.config.PollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-l.stopCh:
				return
			case <-ticker.C:
				l.pollForChanges(ctx)
			}
		}
	}()

	return nil
}

// pollForChanges compares current files with cached checksums.
func (l *Loader) pollForChanges(ctx context.Context) {
	infos, err := l.backend.List(ctx, "**/*.cue")
	if err != nil {
		if l.onError != nil {
			l.onError(err)
		}
		return
	}

	changes := make(map[string]storage.EventType)
	currentPaths := make(map[string]bool)

	l.mu.RLock()
	cachedChecksums := make(map[string]string)
	for k, v := range l.checksums {
		cachedChecksums[k] = v
	}
	l.mu.RUnlock()

	for _, info := range infos {
		if strings.HasSuffix(info.Path, l.config.LockFileExtension) {
			continue
		}

		currentPaths[info.Path] = true

		oldChecksum, existed := cachedChecksums[info.Path]
		newChecksum := info.Checksum
		if newChecksum == "" {
			newChecksum, _ = l.backend.Checksum(ctx, info.Path)
		}

		if !existed {
			changes[info.Path] = storage.EventCreate
		} else if oldChecksum != newChecksum {
			changes[info.Path] = storage.EventModify
		}
	}

	// Check for deleted files
	for path := range cachedChecksums {
		if !currentPaths[path] {
			changes[path] = storage.EventDelete
		}
	}

	if len(changes) > 0 {
		l.processChangedFiles(ctx, changes)
	}
}

// processChangedFiles handles a batch of file changes.
func (l *Loader) processChangedFiles(ctx context.Context, changes map[string]storage.EventType) {
	var reloadedFiles []PolicyFile

	for path, eventType := range changes {
		switch eventType {
		case storage.EventDelete:
			l.mu.Lock()
			delete(l.files, path)
			delete(l.checksums, path)
			l.mu.Unlock()

			l.logger.Debug("policy deleted", zap.String("path", path))

		case storage.EventCreate, storage.EventModify:
			content, err := l.backend.Get(ctx, path)
			if err != nil {
				l.logger.Error("failed to load changed file",
					zap.String("path", path),
					zap.Error(err),
				)
				l.errorCount++
				continue
			}

			checksum, _ := l.backend.Checksum(ctx, path)
			namespace, name := l.deriveNamespaceName(path)

			info, _ := l.backend.Stat(ctx, path)
			modTime := time.Now()
			if info != nil {
				modTime = info.ModTime
			}

			file := PolicyFile{
				Path:      path,
				Namespace: namespace,
				Name:      name,
				Content:   content,
				Checksum:  checksum,
				ModTime:   modTime,
			}

			l.mu.Lock()
			l.files[path] = &file
			l.checksums[path] = checksum
			l.reloadCount++
			l.mu.Unlock()

			reloadedFiles = append(reloadedFiles, file)

			l.logger.Debug("policy reloaded",
				zap.String("path", path),
				zap.String("event", eventType.String()),
			)
		}
	}

	// Notify callback
	if len(reloadedFiles) > 0 && l.onReload != nil {
		if err := l.onReload(reloadedFiles); err != nil {
			l.logger.Error("reload callback failed", zap.Error(err))
		}
	}

	l.logger.Info("policies updated",
		zap.Int("changed", len(changes)),
		zap.Int("reloaded", len(reloadedFiles)),
	)
}

// GetPolicy returns a cached policy, optionally checking for updates.
func (l *Loader) GetPolicy(ctx context.Context, namespace, name string) (*PolicyFile, error) {
	path := l.resolvePath(namespace, name)

	switch l.config.ReloadMode {
	case ReloadJIT:
		return l.getPolicyJIT(ctx, path)
	case ReloadOnDemand:
		return l.getPolicyOnDemand(ctx, path)
	default:
		// Use cached version
		l.mu.RLock()
		defer l.mu.RUnlock()

		if file, ok := l.files[path]; ok {
			return file, nil
		}
		return nil, &storage.ErrNotFound{Path: path}
	}
}

// getPolicyJIT loads a policy just-in-time from storage.
func (l *Loader) getPolicyJIT(ctx context.Context, path string) (*PolicyFile, error) {
	// Check if file has changed
	currentChecksum, err := l.backend.Checksum(ctx, path)
	if err != nil {
		return nil, err
	}

	l.mu.RLock()
	cached, hasCached := l.files[path]
	cachedChecksum := l.checksums[path]
	l.mu.RUnlock()

	// Return cached if unchanged
	if hasCached && cachedChecksum == currentChecksum {
		return cached, nil
	}

	// Load fresh
	content, err := l.backend.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	namespace, name := l.deriveNamespaceName(path)
	info, _ := l.backend.Stat(ctx, path)
	modTime := time.Now()
	if info != nil {
		modTime = info.ModTime
	}

	file := &PolicyFile{
		Path:      path,
		Namespace: namespace,
		Name:      name,
		Content:   content,
		Checksum:  currentChecksum,
		ModTime:   modTime,
	}

	// Update cache
	l.mu.Lock()
	l.files[path] = file
	l.checksums[path] = currentChecksum
	l.mu.Unlock()

	return file, nil
}

// getPolicyOnDemand checks lock file before returning cached policy.
func (l *Loader) getPolicyOnDemand(ctx context.Context, path string) (*PolicyFile, error) {
	lockPath := path + l.config.LockFileExtension

	// Read lock file
	lockContent, err := l.backend.Get(ctx, lockPath)
	if err != nil {
		// No lock file - use cached or load fresh
		l.mu.RLock()
		if cached, ok := l.files[path]; ok {
			l.mu.RUnlock()
			return cached, nil
		}
		l.mu.RUnlock()

		return l.getPolicyJIT(ctx, path)
	}

	// Parse lock file checksum
	lock, err := parseLockFileContent(lockContent)
	if err != nil {
		l.logger.Warn("invalid lock file", zap.String("path", lockPath), zap.Error(err))
		return l.getPolicyJIT(ctx, path)
	}

	// Compare with cached checksum
	l.mu.RLock()
	cached, hasCached := l.files[path]
	cachedChecksum := l.checksums[path]
	l.mu.RUnlock()

	if hasCached && cachedChecksum == lock.Checksum {
		return cached, nil
	}

	// Reload policy
	return l.getPolicyJIT(ctx, path)
}

// deriveNamespaceName determines namespace and name from path.
func (l *Loader) deriveNamespaceName(path string) (namespace, name string) {
	// Extract name from filename
	name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	// Derive namespace based on strategy
	dir := filepath.Dir(path)
	parts := strings.Split(dir, string(filepath.Separator))

	// Filter out empty parts
	var cleanParts []string
	for _, p := range parts {
		if p != "" && p != "." {
			cleanParts = append(cleanParts, p)
		}
	}

	switch l.config.NamespaceStrategy.Mode {
	case "directory":
		depth := l.config.NamespaceStrategy.Depth
		if depth < len(cleanParts) {
			namespace = cleanParts[depth]
		} else if len(cleanParts) > 0 {
			namespace = cleanParts[0]
		} else {
			namespace = l.config.NamespaceStrategy.Default
		}

	case "explicit":
		namespace = l.config.NamespaceStrategy.Default

	case "hybrid":
		if len(cleanParts) > 0 {
			depth := l.config.NamespaceStrategy.Depth
			if depth < len(cleanParts) {
				namespace = cleanParts[depth]
			} else {
				namespace = cleanParts[0]
			}
		} else {
			namespace = l.config.NamespaceStrategy.Default
		}
	}

	// Apply prefix
	if l.config.NamespaceStrategy.Prefix != "" {
		namespace = l.config.NamespaceStrategy.Prefix + namespace
	}

	return namespace, name
}

// resolvePath resolves namespace/name to a storage path.
func (l *Loader) resolvePath(namespace, name string) string {
	// Try common patterns
	patterns := []string{
		filepath.Join(namespace, name+".cue"),
		filepath.Join(namespace, name, "policy.cue"),
		name + ".cue",
	}

	for _, path := range patterns {
		l.mu.RLock()
		_, exists := l.files[path]
		l.mu.RUnlock()

		if exists {
			return path
		}
	}

	// Default
	return filepath.Join(namespace, name+".cue")
}

// Stats returns loader statistics.
func (l *Loader) Stats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return Stats{
		Backend:     l.backend.Type(),
		PolicyCount: len(l.files),
		LoadCount:   l.loadCount,
		ReloadCount: l.reloadCount,
		ErrorCount:  l.errorCount,
	}
}

// Stats contains loader statistics.
type Stats struct {
	Backend     string
	PolicyCount int
	LoadCount   int64
	ReloadCount int64
	ErrorCount  int64
}

// parseLockFileContent parses lock file JSON content.
func parseLockFileContent(content []byte) (*LockFile, error) {
	var lock LockFile
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("invalid lock file JSON: %w", err)
	}
	return &lock, nil
}
