// internal/plugin/manager.go
// Package plugin provides the plugin system for Garmr.
// Plugins extend Q's capabilities without bloating the core binary.
//
// Plugin Types:
//   - storage: Policy storage backends (S3, GCS, DuckDB, Consul, etc.)
//   - auth: Authentication providers (OIDC, LDAP, mTLS, etc.)
//   - notifier: Event notification sinks (Slack, PagerDuty, webhooks, etc.)
//   - function: Custom CUE functions for policy evaluation
//
// Plugin Loading:
//   - Built-in: Compiled into Garmr (filesystem storage always included)
//   - Shared library: .so/.dylib files loaded at runtime
//   - (Future) WASM: Sandboxed WebAssembly plugins
package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goplugin "plugin"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Common errors
var (
	ErrPluginNotFound      = errors.New("plugin not found")
	ErrPluginInvalid       = errors.New("invalid plugin")
	ErrPluginVersionMismatch = errors.New("plugin version mismatch")
	ErrPluginAlreadyLoaded = errors.New("plugin already loaded")
	ErrPluginTypeMismatch  = errors.New("plugin type mismatch")
	ErrPluginDisabled      = errors.New("plugin disabled by configuration")
)

// Type identifies the category of plugin.
type Type string

const (
	TypeStorage  Type = "storage"
	TypeAuth     Type = "auth"
	TypeNotifier Type = "notifier"
	TypeFunction Type = "function"
)

// Metadata describes a plugin.
type Metadata struct {
	// Name is the unique identifier (e.g., "s3", "consul", "duckdb")
	Name string `json:"name"`

	// Type categorizes the plugin
	Type Type `json:"type"`

	// Version using semver (e.g., "1.2.0")
	Version string `json:"version"`

	// Description for documentation
	Description string `json:"description"`

	// Author or maintainer
	Author string `json:"author,omitempty"`

	// License (e.g., "Apache-2.0", "MIT")
	License string `json:"license,omitempty"`

	// Homepage or documentation URL
	Homepage string `json:"homepage,omitempty"`

	// MinQVersion is the minimum Q version required
	MinQVersion string `json:"minQVersion,omitempty"`

	// Capabilities lists what this plugin provides
	Capabilities []string `json:"capabilities,omitempty"`

	// Dependencies on other plugins
	Dependencies []string `json:"dependencies,omitempty"`

	// Checksum of the plugin binary (for verification)
	Checksum string `json:"checksum,omitempty"`

	// Builtin indicates this is compiled into Q
	Builtin bool `json:"builtin"`

	// Annotations for additional metadata (e.g., signature info)
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Plugin is the interface all plugins must implement.
type Plugin interface {
	// Metadata returns plugin information
	Metadata() Metadata

	// Init initializes the plugin with configuration
	Init(ctx context.Context, config map[string]interface{}) error

	// Health checks if the plugin is functioning
	Health(ctx context.Context) error

	// Close releases plugin resources
	Close() error
}

// PluginSymbol is the name of the symbol exported by plugin shared libraries.
// Every .so/.dylib must export: var QPlugin plugin.Plugin
const PluginSymbol = "QPlugin"

// Manager handles plugin registration, loading, and lifecycle.
type Manager struct {
	mu      sync.RWMutex
	plugins map[string]Plugin          // name -> plugin
	meta    map[string]Metadata        // name -> metadata
	loaded  map[string]string          // name -> path (for external plugins)
	config  ManagerConfig
	logger  *zap.Logger

	// Signature verification
	verifier    *Verifier
	trustedKeys *TrustedKeys

	// Type-specific registries
	storageFactories  map[string]StorageFactory
	authFactories     map[string]AuthFactory
	notifierFactories map[string]NotifierFactory
	functionFactories map[string]FunctionFactory
}

// ManagerConfig configures the plugin manager.
type ManagerConfig struct {
	// PluginDir is where external plugins are loaded from
	PluginDir string

	// AllowedPlugins whitelist (empty = allow all)
	AllowedPlugins []string

	// BlockedPlugins blacklist (takes precedence over allowed)
	BlockedPlugins []string

	// AutoDiscover enables scanning PluginDir for plugins
	AutoDiscover bool

	// Signing configuration
	Signing SigningConfig
}

// SigningConfig configures plugin signature verification.
type SigningConfig struct {
	// Required makes signature verification mandatory
	// If true, unsigned plugins will not load
	Required bool

	// TrustedKeysFile path to file containing trusted public keys
	TrustedKeysFile string

	// TrustedKeys are base64-encoded Ed25519 public keys
	// Alternative to TrustedKeysFile for embedding in config
	TrustedKeys []TrustedKeyEntry

	// RejectUntrustedKeys fails if signature exists but key is not trusted
	// If false, untrusted signatures are treated as unsigned
	RejectUntrustedKeys bool
}

// TrustedKeyEntry represents a trusted signing key in configuration.
type TrustedKeyEntry struct {
	// PublicKey is base64-encoded Ed25519 public key
	PublicKey string

	// Comment describes the key (e.g., "Production Signing Key")
	Comment string
}

// NewManager creates a new plugin manager.
func NewManager(cfg ManagerConfig, logger *zap.Logger) (*Manager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	m := &Manager{
		plugins:           make(map[string]Plugin),
		meta:              make(map[string]Metadata),
		loaded:            make(map[string]string),
		config:            cfg,
		logger:            logger,
		storageFactories:  make(map[string]StorageFactory),
		authFactories:     make(map[string]AuthFactory),
		notifierFactories: make(map[string]NotifierFactory),
		functionFactories: make(map[string]FunctionFactory),
	}

	// Initialize trusted keys for signature verification
	trustedKeys := NewTrustedKeys()

	// Load from file if specified
	if cfg.Signing.TrustedKeysFile != "" {
		loaded, err := LoadTrustedKeysFromFile(cfg.Signing.TrustedKeysFile)
		if err != nil {
			return nil, fmt.Errorf("loading trusted keys: %w", err)
		}
		for _, key := range loaded.List() {
			trustedKeys.Add(key)
		}
		logger.Info("loaded trusted keys from file",
			zap.String("file", cfg.Signing.TrustedKeysFile),
			zap.Int("count", len(loaded.List())),
		)
	}

	// Add keys from config
	for _, entry := range cfg.Signing.TrustedKeys {
		if err := trustedKeys.AddFromBase64(entry.PublicKey, entry.Comment); err != nil {
			return nil, fmt.Errorf("adding trusted key: %w", err)
		}
	}

	m.trustedKeys = trustedKeys
	m.verifier = NewVerifier(trustedKeys, cfg.Signing.Required)

	if cfg.Signing.Required {
		logger.Info("plugin signature verification enabled (strict mode)")
	}

	return m, nil
}

// RegisterBuiltin registers a built-in plugin.
func (m *Manager) RegisterBuiltin(p Plugin) error {
	meta := p.Metadata()
	meta.Builtin = true

	return m.register(p, meta, "")
}

// register adds a plugin to the manager.
func (m *Manager) register(p Plugin, meta Metadata, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := meta.Name

	// Check if already loaded
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("%w: %s", ErrPluginAlreadyLoaded, name)
	}

	// Check blocklist
	if m.isBlocked(name) {
		return fmt.Errorf("%w: %s is blocked", ErrPluginDisabled, name)
	}

	// Check allowlist (if configured)
	if !m.isAllowed(name) {
		return fmt.Errorf("%w: %s not in allowed list", ErrPluginDisabled, name)
	}

	m.plugins[name] = p
	m.meta[name] = meta
	if path != "" {
		m.loaded[name] = path
	}

	m.logger.Info("plugin registered",
		zap.String("name", name),
		zap.String("type", string(meta.Type)),
		zap.String("version", meta.Version),
		zap.Bool("builtin", meta.Builtin),
	)

	return nil
}

// LoadFromFile loads a plugin from a shared library file.
func (m *Manager) LoadFromFile(path string) error {
	// Verify file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("accessing plugin file: %w", err)
	}

	// Security: Check file permissions (should not be world-writable)
	if runtime.GOOS != "windows" {
		mode := info.Mode()
		if mode&0002 != 0 { // World-writable
			return fmt.Errorf("%w: file is world-writable", ErrPluginInvalid)
		}
	}

	// Verify signature
	result, err := m.verifier.StreamVerify(path)
	if err != nil {
		// Handle based on error type and configuration
		switch {
		case errors.Is(err, ErrSignatureMissing):
			if m.config.Signing.Required {
				m.logger.Error("plugin rejected: signature required but not found",
					zap.String("path", path),
				)
				return fmt.Errorf("%w: signature required", ErrPluginInvalid)
			}
			m.logger.Warn("loading unsigned plugin",
				zap.String("path", path),
				zap.String("checksum", result.Checksum),
			)

		case errors.Is(err, ErrKeyNotTrusted):
			if m.config.Signing.RejectUntrustedKeys {
				m.logger.Error("plugin rejected: signing key not trusted",
					zap.String("path", path),
					zap.String("keyId", result.KeyID),
				)
				return fmt.Errorf("%w: signing key not trusted", ErrPluginInvalid)
			}
			m.logger.Warn("plugin signed with untrusted key",
				zap.String("path", path),
				zap.String("keyId", result.KeyID),
			)

		case errors.Is(err, ErrSignatureInvalid):
			m.logger.Error("plugin rejected: signature verification failed",
				zap.String("path", path),
				zap.String("keyId", result.KeyID),
			)
			return fmt.Errorf("%w: signature verification failed", ErrPluginInvalid)

		case errors.Is(err, ErrChecksumMismatch):
			m.logger.Error("plugin rejected: checksum mismatch (possible tampering)",
				zap.String("path", path),
			)
			return fmt.Errorf("%w: checksum mismatch", ErrPluginInvalid)

		default:
			return fmt.Errorf("verifying plugin: %w", err)
		}
	} else if result.Verified {
		m.logger.Info("plugin signature verified",
			zap.String("path", path),
			zap.String("keyId", result.KeyID),
			zap.String("keyComment", result.KeyComment),
			zap.Time("signedAt", result.Timestamp),
		)
	}

	// Load the shared library
	plug, err := goplugin.Open(path)
	if err != nil {
		return fmt.Errorf("opening plugin: %w", err)
	}

	// Look up the plugin symbol
	sym, err := plug.Lookup(PluginSymbol)
	if err != nil {
		return fmt.Errorf("plugin missing %s symbol: %w", PluginSymbol, err)
	}

	// Assert the type
	p, ok := sym.(*Plugin)
	if !ok {
		return fmt.Errorf("%w: %s is not a Plugin", ErrPluginInvalid, PluginSymbol)
	}

	meta := (*p).Metadata()
	
	// Store verification info in metadata
	if result.Verified {
		meta.Checksum = result.Checksum
		if meta.Annotations == nil {
			meta.Annotations = make(map[string]string)
		}
		meta.Annotations["signature.keyId"] = result.KeyID
		meta.Annotations["signature.timestamp"] = result.Timestamp.Format(time.RFC3339)
		if result.KeyComment != "" {
			meta.Annotations["signature.keyComment"] = result.KeyComment
		}
	}

	return m.register(*p, meta, path)
}

// LoadFromDir loads all plugins from a directory.
func (m *Manager) LoadFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No plugin directory
		}
		return err
	}

	ext := pluginExtension()
	var loadErrors []error

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ext) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if err := m.LoadFromFile(path); err != nil {
			m.logger.Warn("failed to load plugin",
				zap.String("path", path),
				zap.Error(err),
			)
			loadErrors = append(loadErrors, err)
		}
	}

	if len(loadErrors) > 0 {
		return fmt.Errorf("failed to load %d plugins", len(loadErrors))
	}

	return nil
}

// Get returns a registered plugin by name.
func (m *Manager) Get(name string) (Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.plugins[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return p, nil
}

// GetMetadata returns metadata for a plugin.
func (m *Manager) GetMetadata(name string) (Metadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	meta, ok := m.meta[name]
	if !ok {
		return Metadata{}, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
	}

	return meta, nil
}

// List returns metadata for all registered plugins.
func (m *Manager) List() []Metadata {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Metadata, 0, len(m.meta))
	for _, meta := range m.meta {
		result = append(result, meta)
	}

	return result
}

// ListByType returns plugins of a specific type.
func (m *Manager) ListByType(t Type) []Metadata {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []Metadata
	for _, meta := range m.meta {
		if meta.Type == t {
			result = append(result, meta)
		}
	}

	return result
}

// InitAll initializes all registered plugins.
func (m *Manager) InitAll(ctx context.Context, configs map[string]map[string]interface{}) error {
	m.mu.RLock()
	plugins := make(map[string]Plugin)
	for k, v := range m.plugins {
		plugins[k] = v
	}
	m.mu.RUnlock()

	for name, p := range plugins {
		cfg := configs[name]
		if cfg == nil {
			cfg = make(map[string]interface{})
		}

		if err := p.Init(ctx, cfg); err != nil {
			return fmt.Errorf("initializing plugin %s: %w", name, err)
		}

		m.logger.Debug("plugin initialized", zap.String("name", name))
	}

	return nil
}

// CloseAll closes all registered plugins.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, p := range m.plugins {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// HealthCheck checks health of all plugins.
func (m *Manager) HealthCheck(ctx context.Context) map[string]error {
	m.mu.RLock()
	plugins := make(map[string]Plugin)
	for k, v := range m.plugins {
		plugins[k] = v
	}
	m.mu.RUnlock()

	results := make(map[string]error)
	for name, p := range plugins {
		results[name] = p.Health(ctx)
	}

	return results
}

func (m *Manager) isBlocked(name string) bool {
	for _, blocked := range m.config.BlockedPlugins {
		if blocked == name {
			return true
		}
	}
	return false
}

func (m *Manager) isAllowed(name string) bool {
	// If no allowlist, everything (not blocked) is allowed
	if len(m.config.AllowedPlugins) == 0 {
		return true
	}

	for _, allowed := range m.config.AllowedPlugins {
		if allowed == name {
			return true
		}
	}

	return false
}

func pluginExtension() string {
	switch runtime.GOOS {
	case "darwin":
		return ".dylib"
	case "windows":
		return ".dll"
	default:
		return ".so"
	}
}

// Type-specific factories (to be implemented by plugin types)

// StorageFactory creates storage backends.
type StorageFactory func(config map[string]interface{}) (interface{}, error)

// AuthFactory creates authentication providers.
type AuthFactory func(config map[string]interface{}) (interface{}, error)

// NotifierFactory creates notification sinks.
type NotifierFactory func(config map[string]interface{}) (interface{}, error)

// FunctionFactory creates custom CUE functions.
type FunctionFactory func(config map[string]interface{}) (interface{}, error)

// RegisterStorageFactory registers a storage plugin factory.
func (m *Manager) RegisterStorageFactory(name string, factory StorageFactory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storageFactories[name] = factory
}

// GetStorageFactory returns a storage plugin factory.
func (m *Manager) GetStorageFactory(name string) (StorageFactory, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.storageFactories[name]
	return f, ok
}
