// internal/plugin/builtin.go
// Package plugin provides plugin implementations.
package plugin

import (
	"context"

	"github.com/infrashift/garmr/internal/experimental/storage"
)

// StoragePlugin extends Plugin for storage backends.
type StoragePlugin interface {
	Plugin

	// Backend returns the storage backend instance.
	Backend() storage.Backend
}

// ============================================
// BUILT-IN FILESYSTEM PLUGIN
// ============================================

// FilesystemPlugin is the built-in filesystem storage plugin.
// This is always compiled into Garmr and cannot be disabled.
type FilesystemPlugin struct {
	backend storage.Backend
	config  FilesystemConfig
}

// FilesystemConfig configures the filesystem plugin.
type FilesystemConfig struct {
	Root           string   `json:"root"`
	FollowSymlinks bool     `json:"followSymlinks"`
	IncludePatterns []string `json:"includePatterns"`
	ExcludePatterns []string `json:"excludePatterns"`
}

// NewFilesystemPlugin creates the built-in filesystem plugin.
func NewFilesystemPlugin() *FilesystemPlugin {
	return &FilesystemPlugin{}
}

func (p *FilesystemPlugin) Metadata() Metadata {
	return Metadata{
		Name:        "filesystem",
		Type:        TypeStorage,
		Version:     "1.0.0",
		Description: "Local filesystem storage backend. Supports watching for changes via inotify.",
		Author:      "Garmr",
		License:     "Apache-2.0",
		Builtin:     true,
		Capabilities: []string{
			"storage.read",
			"storage.watch",
			"storage.checksum",
		},
	}
}

func (p *FilesystemPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config
	p.config = FilesystemConfig{
		Root:            "/policies",
		IncludePatterns: []string{"**/*.cue"},
		ExcludePatterns: []string{"**/*_test.cue", "**/testdata/**"},
	}

	if v, ok := config["root"].(string); ok {
		p.config.Root = v
	}
	if v, ok := config["followSymlinks"].(bool); ok {
		p.config.FollowSymlinks = v
	}
	if v, ok := config["includePatterns"].([]string); ok {
		p.config.IncludePatterns = v
	}
	if v, ok := config["excludePatterns"].([]string); ok {
		p.config.ExcludePatterns = v
	}

	// Create storage backend
	backend, err := storage.NewFilesystemBackend(storage.Config{
		Type:            "filesystem",
		Root:            p.config.Root,
		IncludePatterns: p.config.IncludePatterns,
		ExcludePatterns: p.config.ExcludePatterns,
	})
	if err != nil {
		return err
	}

	p.backend = backend
	return nil
}

func (p *FilesystemPlugin) Health(ctx context.Context) error {
	// Check if root directory is accessible
	_, err := p.backend.List(ctx, "")
	return err
}

func (p *FilesystemPlugin) Close() error {
	if p.backend != nil {
		return p.backend.Close()
	}
	return nil
}

func (p *FilesystemPlugin) Backend() storage.Backend {
	return p.backend
}

// Compile-time check
var _ StoragePlugin = (*FilesystemPlugin)(nil)

// ============================================
// PLUGIN REGISTRATION
// ============================================

// RegisterBuiltins registers all built-in plugins with the manager.
func RegisterBuiltins(m *Manager) error {
	// Filesystem is always available
	if err := m.RegisterBuiltin(NewFilesystemPlugin()); err != nil {
		return err
	}

	return nil
}
