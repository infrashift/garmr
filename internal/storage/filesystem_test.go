package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewFilesystemBackend(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{
		Type: "filesystem",
		Root: dir,
	}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	fb := backend.(*FilesystemBackend)
	if fb.Type() != "filesystem" {
		t.Errorf("expected type=filesystem, got %s", fb.Type())
	}
	if fb.Root() != dir {
		t.Errorf("expected root=%s, got %s", dir, fb.Root())
	}
}

func TestNewFilesystemBackend_DefaultRoot(t *testing.T) {
	// Default root is /policies which likely doesn't exist
	cfg := Config{Type: "filesystem"}
	_, err := NewFilesystemBackend(cfg)
	if err == nil {
		t.Error("expected error for non-existent default root")
	}
	var notFoundErr *ErrNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestNewFilesystemBackend_Aliases(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Root: dir}

	for _, alias := range []string{"filesystem", "fs", "file"} {
		cfg.Type = alias
		b, err := New(cfg)
		if err != nil {
			t.Fatalf("New(%s): %v", alias, err)
		}
		if b.Type() != "filesystem" {
			t.Errorf("alias %s: expected type=filesystem, got %s", alias, b.Type())
		}
		b.Close()
	}
}

func TestNewFilesystemBackend_NonexistentRoot(t *testing.T) {
	cfg := Config{
		Type: "filesystem",
		Root: "/nonexistent/path/that/does/not/exist",
	}
	_, err := NewFilesystemBackend(cfg)
	if err == nil {
		t.Fatal("expected error for non-existent root")
	}
	var notFoundErr *ErrNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestFilesystemBackend_List(t *testing.T) {
	dir := t.TempDir()

	// Create CUE files
	os.WriteFile(filepath.Join(dir, "policy1.cue"), []byte("package p\nx: 1"), 0644)
	os.WriteFile(filepath.Join(dir, "policy2.cue"), []byte("package p\ny: 2"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a policy"), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "nested.cue"), []byte("package p\nz: 3"), 0644)

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatalf("NewFilesystemBackend: %v", err)
	}
	defer backend.Close()

	files, err := backend.List(context.Background(), "**/*.cue")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("expected 3 CUE files, got %d", len(files))
		for _, f := range files {
			t.Logf("  %s", f.Path)
		}
	}
}

func TestFilesystemBackend_List_ExcludesTestFiles(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "policy.cue"), []byte("package p\nx: 1"), 0644)
	os.WriteFile(filepath.Join(dir, "policy_test.cue"), []byte("package p\nx: 1"), 0644)

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	files, err := backend.List(context.Background(), "**/*.cue")
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file (test file excluded), got %d", len(files))
	}
}

func TestFilesystemBackend_Get(t *testing.T) {
	dir := t.TempDir()
	content := []byte("package p\nx: 42")
	os.WriteFile(filepath.Join(dir, "policy.cue"), content, 0644)

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	got, err := backend.Get(context.Background(), "policy.cue")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("expected %q, got %q", content, got)
	}
}

func TestFilesystemBackend_Get_NotFound(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	_, err = backend.Get(context.Background(), "nonexistent.cue")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	var notFoundErr *ErrNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestFilesystemBackend_Get_PathTraversal(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	_, err = backend.Get(context.Background(), "../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	var deniedErr *ErrAccessDenied
	if !errors.As(err, &deniedErr) {
		t.Errorf("expected ErrAccessDenied, got %T: %v", err, err)
	}
}

func TestFilesystemBackend_GetReader(t *testing.T) {
	dir := t.TempDir()
	content := []byte("package p\nstreaming: true")
	os.WriteFile(filepath.Join(dir, "stream.cue"), content, 0644)

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	reader, err := backend.GetReader(context.Background(), "stream.cue")
	if err != nil {
		t.Fatalf("GetReader: %v", err)
	}
	defer reader.Close()

	buf := make([]byte, len(content))
	n, _ := reader.Read(buf)
	if string(buf[:n]) != string(content) {
		t.Errorf("expected %q, got %q", content, buf[:n])
	}
}

func TestFilesystemBackend_Stat(t *testing.T) {
	dir := t.TempDir()
	content := []byte("package p\nstat_test: 1")
	os.WriteFile(filepath.Join(dir, "test.cue"), content, 0644)

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	info, err := backend.Stat(context.Background(), "test.cue")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Path != "test.cue" {
		t.Errorf("expected path=test.cue, got %s", info.Path)
	}
	if info.Size != int64(len(content)) {
		t.Errorf("expected size=%d, got %d", len(content), info.Size)
	}
	if info.IsDir {
		t.Error("expected IsDir=false")
	}
}

func TestFilesystemBackend_Checksum(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "check.cue"), []byte("package p\ncheck: 1"), 0644)

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	checksum, err := backend.Checksum(context.Background(), "check.cue")
	if err != nil {
		t.Fatalf("Checksum: %v", err)
	}
	if len(checksum) == 0 {
		t.Error("expected non-empty checksum")
	}
	if checksum[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix, got %s", checksum[:7])
	}
}

func TestFilesystemBackend_Close(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Close without watching should be fine
	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close again should be fine
	if err := backend.Close(); err != nil {
		t.Fatalf("Close again: %v", err)
	}
}

func TestFilesystemBackend_Root(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{Type: "filesystem", Root: dir}
	backend, err := NewFilesystemBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	fb := backend.(*FilesystemBackend)
	if fb.Root() != dir {
		t.Errorf("expected root=%s, got %s", dir, fb.Root())
	}
}

func TestMatchGlobPattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"**/*.cue", "policy.cue", true},
		{"**/*.cue", "sub/policy.cue", true},
		{"**/*.cue", "a/b/c/policy.cue", true},
		{"**/*.cue", "policy.txt", false},
		{"**/*_test.cue", "policy_test.cue", true},
		{"**/*_test.cue", "sub/policy_test.cue", true},
		{"**/*_test.cue", "policy.cue", false},
		{"**/testdata/**", "testdata/file.cue", true},
		{"**/testdata/**", "sub/testdata/file.cue", true},
		{"*.cue", "policy.cue", true},
		{"*.cue", "sub/policy.cue", false}, // standard glob doesn't cross /
	}

	for _, tt := range tests {
		got := matchGlobPattern(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchGlobPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}
