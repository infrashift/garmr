package storage

import (
	"testing"
)

func TestRegistry_Register_Create(t *testing.T) {
	reg := NewRegistry()

	created := false
	reg.Register("test", func(cfg Config) (Backend, error) {
		created = true
		dir := t.TempDir()
		cfg.Root = dir
		return NewFilesystemBackend(cfg)
	})

	cfg := Config{Type: "test"}
	backend, err := reg.Create(cfg)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !created {
		t.Error("expected factory to be called")
	}
	if backend == nil {
		t.Error("expected non-nil backend")
	}
	if backend != nil {
		backend.Close()
	}
}

func TestRegistry_Create_Unknown(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.Create(Config{Type: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
	if _, ok := err.(*ErrUnknownBackend); !ok {
		t.Errorf("expected ErrUnknownBackend, got %T: %v", err, err)
	}
}

func TestDefaultRegistry_FilesystemRegistered(t *testing.T) {
	dir := t.TempDir()

	// The filesystem backend should be registered via init()
	backend, err := New(Config{
		Type: "filesystem",
		Root: dir,
	})
	if err != nil {
		t.Fatalf("New(filesystem): %v", err)
	}
	defer backend.Close()

	if backend.Type() != "filesystem" {
		t.Errorf("expected type=filesystem, got %s", backend.Type())
	}
}

func TestDefaultRegistry_S3Registered(t *testing.T) {
	// Verify the s3 and minio types are registered via init()
	// We can't actually create an S3 backend without a bucket, but we can verify
	// the factory is registered by checking that we get a bucket error, not unknown backend
	_, err := New(Config{
		Type:    "s3",
		Options: map[string]interface{}{},
	})
	if err == nil {
		t.Fatal("expected error (no bucket)")
	}
	if _, ok := err.(*ErrUnknownBackend); ok {
		t.Error("s3 backend should be registered but got ErrUnknownBackend")
	}
}

func TestErrorTypes(t *testing.T) {
	t.Run("ErrNotFound", func(t *testing.T) {
		err := &ErrNotFound{Path: "/test/path"}
		if err.Error() != "file not found: /test/path" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAccessDenied", func(t *testing.T) {
		err := &ErrAccessDenied{Path: "/secret", Reason: "no permission"}
		expected := "access denied: /secret: no permission"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrUnknownBackend", func(t *testing.T) {
		err := &ErrUnknownBackend{Type: "redis"}
		if err.Error() != "unknown storage backend: redis" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}
