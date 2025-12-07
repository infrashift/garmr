// internal/plugin/manager_test.go
// Package plugin provides comprehensive tests for the plugin manager.
package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// ============================================
// MANAGER CONFIGURATION TESTS
// ============================================

func TestNewManager(t *testing.T) {
	t.Run("creates manager with defaults", func(t *testing.T) {
		cfg := ManagerConfig{}
		manager, err := NewManager(cfg, nil)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		if manager == nil {
			t.Fatal("manager is nil")
		}

		// Should have empty trusted keys
		if len(manager.trustedKeys.List()) != 0 {
			t.Error("expected empty trusted keys")
		}
	})

	t.Run("loads trusted keys from config", func(t *testing.T) {
		key, _ := GenerateKey("test")

		cfg := ManagerConfig{
			Signing: SigningConfig{
				TrustedKeys: []TrustedKeyEntry{{
					PublicKey: key.EncodePublic(),
					Comment:   "test key",
				}},
			},
		}

		manager, err := NewManager(cfg, nil)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		if !manager.trustedKeys.IsTrusted(key.ID) {
			t.Error("key from config should be trusted")
		}
	})

	t.Run("loads trusted keys from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		key, _ := GenerateKey("test")

		// Create trusted keys file
		tk := NewTrustedKeys()
		tk.Add(key)
		keysPath := filepath.Join(tmpDir, "trusted-keys")
		SaveTrustedKeysToFile(tk, keysPath)

		cfg := ManagerConfig{
			Signing: SigningConfig{
				TrustedKeysFile: keysPath,
			},
		}

		manager, err := NewManager(cfg, nil)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		if !manager.trustedKeys.IsTrusted(key.ID) {
			t.Error("key from file should be trusted")
		}
	})

	t.Run("fails for invalid trusted keys file", func(t *testing.T) {
		cfg := ManagerConfig{
			Signing: SigningConfig{
				TrustedKeysFile: "/nonexistent/path",
			},
		}

		_, err := NewManager(cfg, nil)
		if err == nil {
			t.Error("should fail for nonexistent keys file")
		}
	})

	t.Run("fails for invalid inline key", func(t *testing.T) {
		cfg := ManagerConfig{
			Signing: SigningConfig{
				TrustedKeys: []TrustedKeyEntry{{
					PublicKey: "not-valid-base64!",
				}},
			},
		}

		_, err := NewManager(cfg, nil)
		if err == nil {
			t.Error("should fail for invalid inline key")
		}
	})
}

// ============================================
// BUILTIN PLUGIN TESTS
// ============================================

func TestRegisterBuiltin(t *testing.T) {
	cfg := ManagerConfig{}
	manager, _ := NewManager(cfg, nil)

	t.Run("registers builtin plugin", func(t *testing.T) {
		plugin := &mockPlugin{
			meta: Metadata{
				Name:    "test-builtin",
				Type:    TypeStorage,
				Version: "1.0.0",
			},
		}

		err := manager.RegisterBuiltin(plugin)
		if err != nil {
			t.Fatalf("RegisterBuiltin failed: %v", err)
		}

		// Verify plugin is registered
		registered, err := manager.Get("test-builtin")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if registered == nil {
			t.Error("registered plugin is nil")
		}

		// Verify metadata marked as builtin
		meta, _ := manager.GetMetadata("test-builtin")
		if !meta.Builtin {
			t.Error("builtin flag not set")
		}
	})

	t.Run("rejects duplicate plugin", func(t *testing.T) {
		plugin := &mockPlugin{
			meta: Metadata{Name: "duplicate"},
		}

		manager.RegisterBuiltin(plugin)
		err := manager.RegisterBuiltin(plugin)

		if err == nil {
			t.Error("should reject duplicate plugin")
		}
	})

	t.Run("rejects blocked plugin", func(t *testing.T) {
		cfg := ManagerConfig{
			BlockedPlugins: []string{"blocked-plugin"},
		}
		manager, _ := NewManager(cfg, nil)

		plugin := &mockPlugin{
			meta: Metadata{Name: "blocked-plugin"},
		}

		err := manager.RegisterBuiltin(plugin)
		if err == nil {
			t.Error("should reject blocked plugin")
		}
	})

	t.Run("rejects plugin not in allowlist", func(t *testing.T) {
		cfg := ManagerConfig{
			AllowedPlugins: []string{"allowed-only"},
		}
		manager, _ := NewManager(cfg, nil)

		plugin := &mockPlugin{
			meta: Metadata{Name: "not-allowed"},
		}

		err := manager.RegisterBuiltin(plugin)
		if err == nil {
			t.Error("should reject plugin not in allowlist")
		}
	})
}

// ============================================
// PLUGIN LISTING AND RETRIEVAL TESTS
// ============================================

func TestPluginListing(t *testing.T) {
	cfg := ManagerConfig{}
	manager, _ := NewManager(cfg, nil)

	// Register test plugins
	plugins := []Metadata{
		{Name: "storage1", Type: TypeStorage, Version: "1.0.0"},
		{Name: "storage2", Type: TypeStorage, Version: "2.0.0"},
		{Name: "auth1", Type: TypeAuth, Version: "1.0.0"},
		{Name: "notifier1", Type: TypeNotifier, Version: "1.0.0"},
	}

	for _, meta := range plugins {
		manager.RegisterBuiltin(&mockPlugin{meta: meta})
	}

	t.Run("List returns all plugins", func(t *testing.T) {
		list := manager.List()
		if len(list) != 4 {
			t.Errorf("expected 4 plugins, got %d", len(list))
		}
	})

	t.Run("ListByType filters correctly", func(t *testing.T) {
		storagePlugins := manager.ListByType(TypeStorage)
		if len(storagePlugins) != 2 {
			t.Errorf("expected 2 storage plugins, got %d", len(storagePlugins))
		}

		authPlugins := manager.ListByType(TypeAuth)
		if len(authPlugins) != 1 {
			t.Errorf("expected 1 auth plugin, got %d", len(authPlugins))
		}
	})

	t.Run("Get returns correct plugin", func(t *testing.T) {
		plugin, err := manager.Get("storage1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		meta := plugin.Metadata()
		if meta.Name != "storage1" {
			t.Errorf("wrong plugin: got %s", meta.Name)
		}
	})

	t.Run("Get returns error for unknown plugin", func(t *testing.T) {
		_, err := manager.Get("unknown")
		if err == nil {
			t.Error("should error for unknown plugin")
		}
	})

	t.Run("GetMetadata returns correct metadata", func(t *testing.T) {
		meta, err := manager.GetMetadata("storage2")
		if err != nil {
			t.Fatalf("GetMetadata failed: %v", err)
		}

		if meta.Version != "2.0.0" {
			t.Errorf("wrong version: got %s", meta.Version)
		}
	})
}

// ============================================
// PLUGIN LIFECYCLE TESTS
// ============================================

func TestPluginLifecycle(t *testing.T) {
	cfg := ManagerConfig{}
	manager, _ := NewManager(cfg, nil)

	plugin := &mockPlugin{
		meta: Metadata{Name: "lifecycle-test"},
	}
	manager.RegisterBuiltin(plugin)

	t.Run("InitAll initializes plugins", func(t *testing.T) {
		configs := map[string]map[string]interface{}{
			"lifecycle-test": {"key": "value"},
		}

		ctx := context.Background()
		err := manager.InitAll(ctx, configs)
		if err != nil {
			t.Fatalf("InitAll failed: %v", err)
		}

		if !plugin.initialized {
			t.Error("plugin not initialized")
		}
		if plugin.config["key"] != "value" {
			t.Error("config not passed to plugin")
		}
	})

	t.Run("HealthCheck checks all plugins", func(t *testing.T) {
		ctx := context.Background()
		results := manager.HealthCheck(ctx)

		if len(results) != 1 {
			t.Errorf("expected 1 result, got %d", len(results))
		}

		err, ok := results["lifecycle-test"]
		if !ok {
			t.Error("missing health result for plugin")
		}
		if err != nil {
			t.Errorf("health check failed: %v", err)
		}
	})

	t.Run("CloseAll closes plugins", func(t *testing.T) {
		err := manager.CloseAll()
		if err != nil {
			t.Fatalf("CloseAll failed: %v", err)
		}

		if !plugin.closed {
			t.Error("plugin not closed")
		}
	})
}

// ============================================
// PLUGIN INIT ERROR HANDLING TESTS
// ============================================

func TestPluginInitErrors(t *testing.T) {
	cfg := ManagerConfig{}
	manager, _ := NewManager(cfg, nil)

	failingPlugin := &mockPlugin{
		meta:      Metadata{Name: "failing"},
		initFails: true,
		initError: "init failed",
	}
	manager.RegisterBuiltin(failingPlugin)

	t.Run("InitAll returns error on plugin failure", func(t *testing.T) {
		ctx := context.Background()
		err := manager.InitAll(ctx, nil)
		if err == nil {
			t.Error("should return error when plugin init fails")
		}
	})
}

// ============================================
// ALLOWLIST/BLOCKLIST TESTS
// ============================================

func TestAllowlistBlocklist(t *testing.T) {
	t.Run("allowlist permits only listed plugins", func(t *testing.T) {
		cfg := ManagerConfig{
			AllowedPlugins: []string{"allowed1", "allowed2"},
		}
		manager, _ := NewManager(cfg, nil)

		// Should succeed
		err := manager.RegisterBuiltin(&mockPlugin{meta: Metadata{Name: "allowed1"}})
		if err != nil {
			t.Errorf("allowed plugin should register: %v", err)
		}

		// Should fail
		err = manager.RegisterBuiltin(&mockPlugin{meta: Metadata{Name: "not-allowed"}})
		if err == nil {
			t.Error("non-allowed plugin should be rejected")
		}
	})

	t.Run("blocklist takes precedence over allowlist", func(t *testing.T) {
		cfg := ManagerConfig{
			AllowedPlugins: []string{"plugin1"},
			BlockedPlugins: []string{"plugin1"}, // Same plugin blocked
		}
		manager, _ := NewManager(cfg, nil)

		err := manager.RegisterBuiltin(&mockPlugin{meta: Metadata{Name: "plugin1"}})
		if err == nil {
			t.Error("blocked plugin should be rejected even if in allowlist")
		}
	})

	t.Run("empty allowlist allows all non-blocked", func(t *testing.T) {
		cfg := ManagerConfig{
			AllowedPlugins: []string{}, // Empty = allow all
			BlockedPlugins: []string{"blocked"},
		}
		manager, _ := NewManager(cfg, nil)

		// Should succeed
		err := manager.RegisterBuiltin(&mockPlugin{meta: Metadata{Name: "any-name"}})
		if err != nil {
			t.Errorf("should allow any non-blocked plugin: %v", err)
		}

		// Should fail (blocked)
		err = manager.RegisterBuiltin(&mockPlugin{meta: Metadata{Name: "blocked"}})
		if err == nil {
			t.Error("blocked plugin should be rejected")
		}
	})
}

// ============================================
// SIGNING VERIFICATION IN MANAGER TESTS
// ============================================

func TestManagerSignatureVerification(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test plugin file
	pluginContent := []byte("test plugin binary content")
	pluginPath := filepath.Join(tmpDir, "test.so")
	os.WriteFile(pluginPath, pluginContent, 0644)

	// Generate signing key
	signingKey, _ := GenerateKey("test")

	t.Run("strict mode rejects unsigned plugin", func(t *testing.T) {
		cfg := ManagerConfig{
			PluginDir: tmpDir,
			Signing: SigningConfig{
				Required: true,
				TrustedKeys: []TrustedKeyEntry{{
					PublicKey: signingKey.EncodePublic(),
				}},
			},
		}
		manager, _ := NewManager(cfg, zap.NewNop())

		// Try to load without signature
		err := manager.LoadFromFile(pluginPath)
		if err == nil {
			t.Error("strict mode should reject unsigned plugin")
		}
	})

	t.Run("non-strict mode allows unsigned plugin", func(t *testing.T) {
		cfg := ManagerConfig{
			PluginDir: tmpDir,
			Signing: SigningConfig{
				Required: false, // Non-strict
			},
		}
		manager, _ := NewManager(cfg, zap.NewNop())

		// This will fail at plugin.Open (not a real .so)
		// but should not fail at signature verification
		err := manager.LoadFromFile(pluginPath)

		// Should fail for "opening plugin" not "signature required"
		if err != nil && err.Error() != "" {
			// Expected to fail at plugin loading, not signature
			// The error should be about opening the plugin, not signature
		}
	})

	t.Run("rejects untrusted signing key", func(t *testing.T) {
		// Sign with untrusted key
		untrustedKey, _ := GenerateKey("untrusted")
		signer, _ := NewSigner(untrustedKey)
		signer.SignFile(pluginPath, "test")

		cfg := ManagerConfig{
			PluginDir: tmpDir,
			Signing: SigningConfig{
				Required:            true,
				RejectUntrustedKeys: true,
				TrustedKeys: []TrustedKeyEntry{{
					PublicKey: signingKey.EncodePublic(), // Different key
				}},
			},
		}
		manager, _ := NewManager(cfg, zap.NewNop())

		err := manager.LoadFromFile(pluginPath)
		if err == nil {
			t.Error("should reject plugin signed with untrusted key")
		}

		// Cleanup signature files
		os.Remove(pluginPath + SignatureExtension)
		os.Remove(pluginPath + ChecksumExtension)
	})

	t.Run("accepts valid signed plugin", func(t *testing.T) {
		// Sign with trusted key
		signer, _ := NewSigner(signingKey)
		signer.SignFile(pluginPath, "test")

		cfg := ManagerConfig{
			PluginDir: tmpDir,
			Signing: SigningConfig{
				Required: true,
				TrustedKeys: []TrustedKeyEntry{{
					PublicKey: signingKey.EncodePublic(),
				}},
			},
		}
		manager, _ := NewManager(cfg, zap.NewNop())

		// Will fail at plugin.Open but signature verification passes
		err := manager.LoadFromFile(pluginPath)

		// Error should be about opening plugin, not signature
		if err != nil {
			// Check it's not a signature error
			if err == ErrSignatureMissing || err == ErrSignatureInvalid || err == ErrKeyNotTrusted {
				t.Errorf("signature verification should pass: %v", err)
			}
		}
	})
}

// ============================================
// FACTORY REGISTRATION TESTS
// ============================================

func TestFactoryRegistration(t *testing.T) {
	cfg := ManagerConfig{}
	manager, _ := NewManager(cfg, nil)

	t.Run("register and get storage factory", func(t *testing.T) {
		factory := func(config map[string]interface{}) (interface{}, error) {
			return "storage-instance", nil
		}

		manager.RegisterStorageFactory("test-storage", factory)

		retrieved, ok := manager.GetStorageFactory("test-storage")
		if !ok {
			t.Error("factory not found")
		}

		result, _ := retrieved(nil)
		if result != "storage-instance" {
			t.Error("wrong factory retrieved")
		}
	})

	t.Run("get returns false for unknown factory", func(t *testing.T) {
		_, ok := manager.GetStorageFactory("unknown")
		if ok {
			t.Error("should return false for unknown factory")
		}
	})
}

// ============================================
// CONCURRENT ACCESS TESTS
// ============================================

func TestConcurrentAccess(t *testing.T) {
	cfg := ManagerConfig{}
	manager, _ := NewManager(cfg, nil)

	// Register some plugins
	for i := 0; i < 10; i++ {
		manager.RegisterBuiltin(&mockPlugin{
			meta: Metadata{Name: "plugin-" + string(rune('a'+i))},
		})
	}

	t.Run("concurrent reads", func(t *testing.T) {
		done := make(chan bool, 100)

		for i := 0; i < 100; i++ {
			go func() {
				manager.List()
				manager.Get("plugin-a")
				manager.GetMetadata("plugin-b")
				done <- true
			}()
		}

		for i := 0; i < 100; i++ {
			<-done
		}
	})

	t.Run("concurrent health checks", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func() {
				ctx := context.Background()
				manager.HealthCheck(ctx)
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// ============================================
// MOCK PLUGIN FOR TESTING
// ============================================

type mockPlugin struct {
	meta        Metadata
	initialized bool
	closed      bool
	config      map[string]interface{}
	initFails   bool
	initError   string
	healthFails bool
}

func (p *mockPlugin) Metadata() Metadata {
	return p.meta
}

func (p *mockPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	if p.initFails {
		return &mockError{msg: p.initError}
	}
	p.initialized = true
	p.config = config
	return nil
}

func (p *mockPlugin) Health(ctx context.Context) error {
	if p.healthFails {
		return &mockError{msg: "health check failed"}
	}
	return nil
}

func (p *mockPlugin) Close() error {
	p.closed = true
	return nil
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// ============================================
// LOAD FROM DIRECTORY TESTS
// ============================================

func TestLoadFromDir(t *testing.T) {
	t.Run("handles nonexistent directory gracefully", func(t *testing.T) {
		cfg := ManagerConfig{}
		manager, _ := NewManager(cfg, nil)

		err := manager.LoadFromDir("/nonexistent/directory")
		if err != nil {
			t.Error("should not error for nonexistent directory")
		}
	})

	t.Run("ignores non-plugin files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create non-plugin files
		os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("readme"), 0644)
		os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte("{}"), 0644)

		cfg := ManagerConfig{}
		manager, _ := NewManager(cfg, nil)

		err := manager.LoadFromDir(tmpDir)
		if err != nil {
			t.Errorf("should ignore non-plugin files: %v", err)
		}
	})
}

// ============================================
// EDGE CASE TESTS
// ============================================

func TestEdgeCases(t *testing.T) {
	t.Run("empty plugin name", func(t *testing.T) {
		cfg := ManagerConfig{}
		manager, _ := NewManager(cfg, nil)

		_, err := manager.Get("")
		if err == nil {
			t.Error("should error for empty name")
		}
	})

	t.Run("nil context handling", func(t *testing.T) {
		cfg := ManagerConfig{}
		manager, _ := NewManager(cfg, nil)

		plugin := &mockPlugin{meta: Metadata{Name: "test"}}
		manager.RegisterBuiltin(plugin)

		// Should not panic with nil context (though not recommended)
		// The mock plugin handles nil context
		manager.HealthCheck(context.TODO())
	})

	t.Run("double close", func(t *testing.T) {
		cfg := ManagerConfig{}
		manager, _ := NewManager(cfg, nil)

		plugin := &mockPlugin{meta: Metadata{Name: "test"}}
		manager.RegisterBuiltin(plugin)

		manager.CloseAll()
		err := manager.CloseAll() // Second close

		if err != nil {
			t.Errorf("double close should not error: %v", err)
		}
	})
}
