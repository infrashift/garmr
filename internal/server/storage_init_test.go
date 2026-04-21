package server

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/observability"
)

func mkServerForStorage(t *testing.T, cfg Config) *Server {
	t.Helper()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return &Server{
		config: cfg,
		engine: eng,
		logger: zap.NewNop(),
		obs:    observability.NewProvider(),
	}
}

func TestInitStorageBackend_None(t *testing.T) {
	s := mkServerForStorage(t, Config{})
	if err := s.initStorageBackend(); err != nil {
		t.Fatalf("expected nil error for unconfigured storage, got %v", err)
	}
	if s.storageBackend != nil {
		t.Errorf("expected no backend initialized")
	}
}

func TestInitStorageBackend_FilesystemViaPolicyDir(t *testing.T) {
	tmp := t.TempDir()
	s := mkServerForStorage(t, Config{PolicyDir: tmp})
	if err := s.initStorageBackend(); err != nil {
		t.Fatalf("initStorageBackend: %v", err)
	}
	if s.storageBackend == nil {
		t.Fatal("expected filesystem backend")
	}
	if got := s.storageBackend.Type(); got != "filesystem" {
		t.Errorf("expected filesystem, got %s", got)
	}
}

func TestInitStorageBackend_FilesystemViaType(t *testing.T) {
	tmp := t.TempDir()
	s := mkServerForStorage(t, Config{StorageType: "filesystem", StorageRoot: tmp})
	if err := s.initStorageBackend(); err != nil {
		t.Fatalf("initStorageBackend: %v", err)
	}
	if s.storageBackend == nil || s.storageBackend.Type() != "filesystem" {
		t.Errorf("expected filesystem backend, got %#v", s.storageBackend)
	}
}

func TestInitStorageBackend_UnknownTypeError(t *testing.T) {
	s := mkServerForStorage(t, Config{StorageType: "nonsense"})
	err := s.initStorageBackend()
	if err == nil {
		t.Fatal("expected error for unknown storage type")
	}
	if !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("expected error to mention the bad type, got %q", err)
	}
}

func TestStorageType_BackendTakesPrecedence(t *testing.T) {
	tmp := t.TempDir()
	s := mkServerForStorage(t, Config{PolicyDir: tmp})
	if err := s.initStorageBackend(); err != nil {
		t.Fatalf("initStorageBackend: %v", err)
	}
	if got := s.storageType(); got != "filesystem" {
		t.Errorf("expected filesystem, got %q", got)
	}
}
