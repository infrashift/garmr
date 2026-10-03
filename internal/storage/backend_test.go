package storage

import (
	"errors"
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
	var unknownErr *ErrUnknownBackend
	if !errors.As(err, &unknownErr) {
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

// TestDefaultRegistry_UnregisteredTypes documents which backend names are
// deliberately absent. The S3/MinIO backend was removed; see TODO.md for the
// rationale and for what a revival would need. The supported path for object
// storage is to sync objects to disk (init container, CSI mount) and point
// --policy-dir at the result.
func TestDefaultRegistry_UnregisteredTypes(t *testing.T) {
	for _, typ := range []string{"s3", "minio", "gcs", "azure"} {
		t.Run(typ, func(t *testing.T) {
			_, err := New(Config{Type: typ})
			if err == nil {
				t.Fatalf("New(%q) succeeded; that backend is not implemented", typ)
			}
			var unknown *ErrUnknownBackend
			if !errors.As(err, &unknown) {
				t.Errorf("New(%q) error = %v, want ErrUnknownBackend", typ, err)
			}
		})
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
