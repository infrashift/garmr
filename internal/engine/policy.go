package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/load"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/storage"
)

// ListPolicies returns all loaded policies.
func (e *Engine) ListPolicies(namespace string) []*CompiledPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*CompiledPolicy
	for _, p := range e.policies {
		if namespace == "" || p.Namespace == namespace {
			result = append(result, p)
		}
	}
	return result
}

// GetPolicy returns a specific policy.
func (e *Engine) GetPolicy(namespace, name string) (*CompiledPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	key := policyKey(namespace, name)
	if p, ok := e.policies[key]; ok {
		return p, nil
	}
	return nil, ErrPolicyNotFound
}

// DeletePolicy removes a policy.
func (e *Engine) DeletePolicy(namespace, name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := policyKey(namespace, name)
	if _, ok := e.policies[key]; ok {
		delete(e.policies, key)
		return true
	}
	return false
}

// ClearPolicies removes all loaded policies.
func (e *Engine) ClearPolicies() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = make(map[string]*CompiledPolicy)
	e.logger.Info("cleared all policies")
}

// ReloadPoliciesFromDir atomically reloads all policies from a directory.
// This is safe to call while evaluations are in progress - in-flight evaluations
// will complete with the old policy set, new evaluations will use the new set.
func (e *Engine) ReloadPoliciesFromDir(ctx context.Context, dir string) (int, error) {
	// Load into a new map (no lock needed during load)
	newPolicies := make(map[string]*CompiledPolicy)

	if err := e.loadPoliciesIntoMap(ctx, dir, newPolicies); err != nil {
		return 0, err
	}

	// Atomic swap - only hold lock briefly
	e.mu.Lock()
	e.policies = newPolicies
	e.mu.Unlock()

	e.logger.Info("policies reloaded atomically", zap.Int("count", len(newPolicies)))
	return len(newPolicies), nil
}

// loadPoliciesIntoMap loads policies into the provided map (no locking).
func (e *Engine) loadPoliciesIntoMap(ctx context.Context, dir string, policies map[string]*CompiledPolicy) error {
	// Load from the directory itself
	if err := e.loadSingleDirIntoMap(ctx, dir, policies); err != nil {
		e.logger.Debug("no policies in root, scanning subdirectories", zap.String("dir", dir))
	}

	// Walk subdirectories
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "cue.mod" {
			continue
		}

		subdir := filepath.Join(dir, name)

		hasCueFiles, _ := e.hasCueFiles(subdir)
		if hasCueFiles {
			if err := e.loadSingleDirIntoMap(ctx, subdir, policies); err != nil {
				e.logger.Warn("failed to load policies from subdirectory",
					zap.String("dir", subdir),
					zap.Error(err),
				)
				continue
			}
		} else {
			// Recursively check deeper
			e.loadPoliciesIntoMap(ctx, subdir, policies)
		}
	}

	return nil
}

// loadSingleDirIntoMap loads policies from a single directory into the map.
func (e *Engine) loadSingleDirIntoMap(ctx context.Context, dir string, policies map[string]*CompiledPolicy) error {
	// Use pooled context since this may be called without the engine lock
	// (e.g., from ReloadPoliciesFromDir).
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	cfg := &load.Config{
		Dir: dir,
	}

	instances := load.Instances([]string{"."}, cfg)
	loadedAny := false

	for _, inst := range instances {
		if inst.Err != nil {
			return fmt.Errorf("loading instance: %w", inst.Err)
		}

		val := cueCtx.BuildInstance(inst)
		if val.Err() != nil {
			return fmt.Errorf("building instance: %w", val.Err())
		}

		iter, _ := val.Fields()
		for iter.Next() {
			fieldVal := iter.Value()

			kindVal := fieldVal.LookupPath(cue.ParsePath("kind"))
			if !kindVal.Exists() {
				continue
			}

			kind, _ := kindVal.String()
			if kind != "Policy" {
				continue
			}

			nameVal := fieldVal.LookupPath(cue.ParsePath("metadata.name"))
			nsVal := fieldVal.LookupPath(cue.ParsePath("metadata.namespace"))

			name, _ := nameVal.String()
			ns := "default"
			if nsVal.Exists() {
				ns, _ = nsVal.String()
			}

			compiled, err := e.compilePolicy(fieldVal, name, ns)
			if err != nil {
				e.logger.Warn("skipping invalid policy",
					zap.String("name", name),
					zap.Error(err),
				)
				continue
			}

			compiled.LoadedAt = time.Now()
			key := policyKey(ns, name)
			policies[key] = compiled
			loadedAny = true

			e.logger.Info("loaded policy from directory",
				zap.String("name", name),
				zap.String("namespace", ns),
			)
		}
	}

	if !loadedAny {
		return fmt.Errorf("no policies found in %s", dir)
	}

	return nil
}

// Validate validates a policy without loading it.
func (e *Engine) Validate(source string) ([]ValidationError, []ValidationError) {
	// Use pooled context for thread-safe concurrent validation
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	val := cueCtx.CompileString(source)
	if val.Err() != nil {
		return []ValidationError{{
			Message: val.Err().Error(),
			Code:    "PARSE_ERROR",
		}}, nil
	}

	unified := val.Unify(e.schema.LookupPath(cue.ParsePath("#Policy")))
	if unified.Err() != nil {
		return []ValidationError{{
			Message: unified.Err().Error(),
			Code:    "SCHEMA_ERROR",
		}}, nil
	}

	return nil, nil
}

// policyKey creates a unique key for a policy.
func policyKey(namespace, name string) string {
	if namespace == "" {
		namespace = "default"
	}
	return namespace + "/" + name
}

// LoadPoliciesFromDir loads all policies from a directory and its subdirectories.
func (e *Engine) LoadPoliciesFromDir(ctx context.Context, dir string) error {
	// First, try to load from the directory itself
	if err := e.loadPoliciesFromSingleDir(ctx, dir); err != nil {
		// If it fails, it might be a parent directory - try subdirectories
		e.logger.Debug("no policies in root, scanning subdirectories", zap.String("dir", dir))
	}

	// Walk subdirectories to find more policies
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Skip hidden directories and common non-policy directories
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "cue.mod" {
			continue
		}

		subdir := filepath.Join(dir, name)

		// Check if subdirectory contains .cue files
		hasCueFiles, _ := e.hasCueFiles(subdir)
		if hasCueFiles {
			if err := e.loadPoliciesFromSingleDir(ctx, subdir); err != nil {
				e.logger.Warn("failed to load policies from subdirectory",
					zap.String("dir", subdir),
					zap.Error(err),
				)
				// Continue with other directories
				continue
			}
		} else {
			// Recursively check deeper directories
			if err := e.LoadPoliciesFromDir(ctx, subdir); err != nil {
				e.logger.Debug("no policies in subdirectory", zap.String("dir", subdir))
			}
		}
	}

	return nil
}

// hasCueFiles checks if a directory contains .cue files
func (e *Engine) hasCueFiles(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cue") {
			return true, nil
		}
	}
	return false, nil
}

// loadPoliciesFromSingleDir loads policies from a single directory (non-recursive)
func (e *Engine) loadPoliciesFromSingleDir(ctx context.Context, dir string) error {
	// Use pooled context for thread safety during reload operations
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	cfg := &load.Config{
		Dir: dir,
	}

	instances := load.Instances([]string{"."}, cfg)
	loadedAny := false

	// Track namespaces that got policies loaded for metrics
	namespaceCounts := make(map[string]int)

	for _, inst := range instances {
		if inst.Err != nil {
			e.obs.Metrics().RecordPolicyLoadError("", dir, "compilation")
			return fmt.Errorf("loading instance: %w", inst.Err)
		}

		val := cueCtx.BuildInstance(inst)
		if val.Err() != nil {
			e.obs.Metrics().RecordPolicyLoadError("", dir, "compilation")
			return fmt.Errorf("building instance: %w", val.Err())
		}

		// Iterate fields to find policies
		iter, _ := val.Fields()
		for iter.Next() {
			fieldVal := iter.Value()

			// Check if this is a policy
			kindVal := fieldVal.LookupPath(cue.ParsePath("kind"))
			if !kindVal.Exists() {
				continue
			}

			kind, _ := kindVal.String()
			if kind != "Policy" {
				continue
			}

			// Extract name
			nameVal := fieldVal.LookupPath(cue.ParsePath("metadata.name"))
			nsVal := fieldVal.LookupPath(cue.ParsePath("metadata.namespace"))

			name, _ := nameVal.String()
			ns := "default"
			if nsVal.Exists() {
				ns, _ = nsVal.String()
			}

			compiled, err := e.compilePolicy(fieldVal, name, ns)
			if err != nil {
				e.obs.Metrics().RecordPolicyLoadError(name, ns, "compilation")
				e.logger.Warn("skipping invalid policy",
					zap.String("name", name),
					zap.Error(err),
				)
				continue
			}

			compiled.LoadedAt = time.Now()
			key := policyKey(ns, name)
			e.policies[key] = compiled
			loadedAny = true
			namespaceCounts[ns]++

			e.logger.Info("loaded policy from directory",
				zap.String("name", name),
				zap.String("namespace", ns),
			)
		}
	}

	if !loadedAny {
		return fmt.Errorf("no policies found in %s", dir)
	}

	// Record loaded policy counts per namespace
	for ns, count := range namespaceCounts {
		e.obs.Metrics().SetPoliciesLoaded(ns, count)
	}

	return nil
}

// LoadPoliciesFromBackend loads all policies from a storage backend.
// For FilesystemBackend, this delegates directly to LoadPoliciesFromDir (zero overhead).
// For other backends, files are staged to a temp directory then loaded via CUE.
func (e *Engine) LoadPoliciesFromBackend(ctx context.Context, backend storage.Backend) error {
	// Filesystem shortcut: use the root directory directly
	if fsBackend, ok := backend.(*storage.FilesystemBackend); ok {
		return e.LoadPoliciesFromDir(ctx, fsBackend.Root())
	}

	// Other backends: stage files to temp dir, then load
	tempDir, cleanup, err := e.stageBackendFiles(ctx, backend)
	if err != nil {
		return fmt.Errorf("staging backend files: %w", err)
	}
	defer cleanup()

	return e.LoadPoliciesFromDir(ctx, tempDir)
}

// ReloadPoliciesFromBackend atomically reloads all policies from a storage backend.
// This is safe to call while evaluations are in progress.
func (e *Engine) ReloadPoliciesFromBackend(ctx context.Context, backend storage.Backend) (int, error) {
	// Filesystem shortcut: use the root directory directly
	if fsBackend, ok := backend.(*storage.FilesystemBackend); ok {
		return e.ReloadPoliciesFromDir(ctx, fsBackend.Root())
	}

	// Other backends: stage files to temp dir, then reload
	tempDir, cleanup, err := e.stageBackendFiles(ctx, backend)
	if err != nil {
		return 0, fmt.Errorf("staging backend files: %w", err)
	}
	defer cleanup()

	// Load into a new map
	newPolicies := make(map[string]*CompiledPolicy)
	if err := e.loadPoliciesIntoMap(ctx, tempDir, newPolicies); err != nil {
		return 0, err
	}

	// Atomic swap
	e.mu.Lock()
	e.policies = newPolicies
	e.mu.Unlock()

	e.logger.Info("policies reloaded from backend",
		zap.String("backend", backend.Type()),
		zap.Int("count", len(newPolicies)),
	)
	return len(newPolicies), nil
}

// stageBackendFiles downloads CUE files from a backend into a temp directory,
// preserving the directory structure. Returns the temp dir path, a cleanup function,
// and any error.
func (e *Engine) stageBackendFiles(ctx context.Context, backend storage.Backend) (string, func(), error) {
	files, err := backend.List(ctx, "**/*.cue")
	if err != nil {
		return "", func() {}, fmt.Errorf("listing backend files: %w", err)
	}

	if len(files) == 0 {
		return "", func() {}, fmt.Errorf("no CUE files found in backend %s", backend.Type())
	}

	tempDir, err := os.MkdirTemp("", "garmr-policies-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("creating temp directory: %w", err)
	}

	cleanup := func() { os.RemoveAll(tempDir) }

	for _, file := range files {
		content, err := backend.Get(ctx, file.Path)
		if err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("reading %s from backend: %w", file.Path, err)
		}

		destPath := filepath.Join(tempDir, filepath.FromSlash(file.Path))

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("creating directory for %s: %w", file.Path, err)
		}

		if err := os.WriteFile(destPath, content, 0644); err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("writing %s: %w", file.Path, err)
		}
	}

	e.logger.Debug("staged backend files",
		zap.String("backend", backend.Type()),
		zap.Int("files", len(files)),
		zap.String("tempDir", tempDir),
	)

	return tempDir, cleanup, nil
}
