package engine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/storage"
)

const backendTestPolicy = `package policy

backend_test: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "backend-test"
		namespace: "default"
	}
	spec: {
		description: "Test policy loaded via backend"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "bt-1"
			description: "check x"
			severity:    "low"
			expr: {match: {path: "x", equals: 1}}
			message: "x must be 1"
		}]
		enforcement: action: "deny"
	}
}
`

func TestLoadPoliciesFromBackend_Filesystem(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(backendTestPolicy), 0644)

	backend, err := storage.NewFilesystemBackend(storage.Config{
		Type: "filesystem",
		Root: dir,
	})
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	defer backend.Close()

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPoliciesFromBackend(context.Background(), backend)
	if err != nil {
		t.Fatalf("LoadPoliciesFromBackend: %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) == 0 {
		t.Error("expected at least 1 policy loaded from filesystem backend")
	}

	p, err := eng.GetPolicy("default", "backend-test")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.Name != "backend-test" {
		t.Errorf("expected name=backend-test, got %s", p.Name)
	}
}

func TestReloadPoliciesFromBackend_Filesystem(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte(backendTestPolicy), 0644)

	backend, err := storage.NewFilesystemBackend(storage.Config{
		Type: "filesystem",
		Root: dir,
	})
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	defer backend.Close()

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	count, err := eng.ReloadPoliciesFromBackend(context.Background(), backend)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromBackend: %v", err)
	}
	if count == 0 {
		t.Error("expected at least 1 policy reloaded")
	}

	// Verify the policy is accessible
	policies := eng.ListPolicies("")
	if len(policies) != count {
		t.Errorf("expected %d policies, got %d", count, len(policies))
	}
}

// mockBackend implements storage.Backend for testing without filesystem.
type mockBackend struct {
	files map[string][]byte
}

func newMockBackend(files map[string][]byte) *mockBackend {
	return &mockBackend{files: files}
}

func (m *mockBackend) Type() string { return "mock" }

func (m *mockBackend) List(ctx context.Context, pattern string) ([]storage.FileInfo, error) {
	var result []storage.FileInfo
	for path, content := range m.files {
		result = append(result, storage.FileInfo{
			Path:    path,
			Size:    int64(len(content)),
			ModTime: time.Now(),
		})
	}
	return result, nil
}

func (m *mockBackend) Get(ctx context.Context, path string) ([]byte, error) {
	content, ok := m.files[path]
	if !ok {
		return nil, &storage.ErrNotFound{Path: path}
	}
	return content, nil
}

func (m *mockBackend) GetReader(ctx context.Context, path string) (io.ReadCloser, error) {
	return nil, nil
}

func (m *mockBackend) Stat(ctx context.Context, path string) (*storage.FileInfo, error) {
	return nil, nil
}

func (m *mockBackend) Checksum(ctx context.Context, path string) (string, error) {
	return "", nil
}

func (m *mockBackend) Close() error { return nil }

func TestLoadPoliciesFromBackend_MockBackend(t *testing.T) {
	mock := newMockBackend(map[string][]byte{
		"security/policy.cue": []byte(backendTestPolicy),
	})

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPoliciesFromBackend(context.Background(), mock)
	if err != nil {
		t.Fatalf("LoadPoliciesFromBackend(mock): %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) == 0 {
		t.Error("expected at least 1 policy loaded from mock backend")
	}
}

func TestStageBackendFiles(t *testing.T) {
	mock := newMockBackend(map[string][]byte{
		"policy.cue":         []byte("package p\nx: 1"),
		"sub/nested.cue":     []byte("package sub\ny: 2"),
		"deep/a/b/three.cue": []byte("package b\nz: 3"),
	})

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tempDir, cleanup, err := eng.stageBackendFiles(context.Background(), mock)
	if err != nil {
		t.Fatalf("stageBackendFiles: %v", err)
	}
	defer cleanup()

	// Verify files exist in temp dir
	for path := range mock.files {
		fullPath := filepath.Join(tempDir, filepath.FromSlash(path))
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Errorf("expected file at %s", fullPath)
		}
	}
}

func TestLoadPoliciesFromBackend_EmptyBackend(t *testing.T) {
	mock := newMockBackend(map[string][]byte{})

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPoliciesFromBackend(context.Background(), mock)
	if err == nil {
		t.Error("expected error for empty backend")
	}
}

// errBackend always returns an error on List.
type errBackend struct{ mockBackend }

func (e *errBackend) List(ctx context.Context, pattern string) ([]storage.FileInfo, error) {
	return nil, &storage.ErrAccessDenied{Path: "/", Reason: "test error"}
}

func TestLoadPoliciesFromBackend_BackendError(t *testing.T) {
	backend := &errBackend{}

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPoliciesFromBackend(context.Background(), backend)
	if err == nil {
		t.Error("expected error when backend.List fails")
	}
}

func TestReloadPoliciesFromBackend_MockBackend(t *testing.T) {
	mock := newMockBackend(map[string][]byte{
		"policy.cue": []byte(backendTestPolicy),
	})

	eng, err := NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Load initial policy via string
	eng.LoadPolicy(context.Background(), "old-policy", "default",
		makePolicy("old-policy", "default", "old", `{id: "r1", description: "old", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}`, "deny", ""))

	if len(eng.ListPolicies("")) != 1 {
		t.Fatal("expected 1 initial policy")
	}

	// Reload from mock backend
	count, err := eng.ReloadPoliciesFromBackend(context.Background(), mock)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromBackend: %v", err)
	}
	if count == 0 {
		t.Error("expected at least 1 reloaded policy")
	}

	// Old policy should be gone (atomic swap)
	_, err = eng.GetPolicy("default", "old-policy")
	if err != ErrPolicyNotFound {
		t.Error("expected old-policy to be replaced after reload")
	}

	// New policy should be present
	_, err = eng.GetPolicy("default", "backend-test")
	if err != nil {
		t.Errorf("expected backend-test policy after reload, got: %v", err)
	}
}
