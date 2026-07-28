package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/storage"
)

// ListPolicies returns all loaded policies.
//
// The returned CompiledPolicy values must be treated as read-only metadata
// snapshots; their CUE values belong to a pooled replica context.
func (e *Engine) ListPolicies(namespace string) []*CompiledPolicy {
	set := e.currentSet()
	rep := set.get()
	defer set.put(rep)

	var result []*CompiledPolicy
	for _, p := range rep.policies {
		if namespace == "" || p.Namespace == namespace {
			result = append(result, p)
		}
	}
	return result
}

// GetPolicy returns a specific policy (read-only metadata snapshot).
func (e *Engine) GetPolicy(namespace, name string) (*CompiledPolicy, error) {
	set := e.currentSet()
	rep := set.get()
	defer set.put(rep)

	key := policyKey(namespace, name)
	if p, ok := rep.policies[key]; ok {
		return p, nil
	}
	return nil, ErrPolicyNotFound
}

// errNoPoliciesFound marks a directory that yielded zero policy documents.
// The walker treats it as "keep scanning"; every other load error is a real
// failure and aborts the load.
var errNoPoliciesFound = errors.New("no policies found")

// DeletePolicy removes a policy.
func (e *Engine) DeletePolicy(namespace, name string) bool {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()

	key := policyKey(namespace, name)
	found := false
	// Cannot fail, so forEachExclusive is fine here; the error is discarded
	// deliberately rather than by omission.
	_ = e.set.forEachExclusive(func(i int, r *policyReplica) error {
		if _, ok := r.policies[key]; ok {
			delete(r.policies, key)
			if i == 0 {
				found = true
			}
		}
		return nil
	})
	return found
}

// ClearPolicies removes all loaded policies.
func (e *Engine) ClearPolicies() {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()

	// Cannot fail; see DeletePolicy.
	_ = e.set.forEachExclusive(func(i int, r *policyReplica) error {
		r.policies = make(map[string]*CompiledPolicy)
		return nil
	})
	e.logger.Info("cleared all policies")
}

// ReloadPoliciesFromDir atomically reloads all policies from a directory.
// This is safe to call while evaluations are in progress - in-flight evaluations
// will complete with the old policy set, new evaluations will use the new set.
//
// Any failure — a policy that does not compile or validate, or a directory
// tree yielding zero policies — leaves the existing set live and returns the
// error. Swapping in an empty or partial set on a bad deploy would silently
// deny (or skip) everything, which is an outage a 200 response would hide.
func (e *Engine) ReloadPoliciesFromDir(ctx context.Context, dir string) (int, error) {
	// Serialize against every other mutation for the whole build+swap window:
	// concurrent reloads must not race their swaps, and an incremental
	// LoadPolicy/DeletePolicy applied to the old set while a new set is being
	// built would be silently discarded by the swap.
	e.loadMu.Lock()
	defer e.loadMu.Unlock()

	newSet, err := newPolicySet(defaultReplicaCount())
	if err != nil {
		return 0, err
	}

	count := 0
	if err := newSet.mutateAll(func(i int, r *policyReplica) (func(), error) {
		pending := make(map[string]*CompiledPolicy)
		if err := e.loadDirIntoReplica(ctx, dir, r, i != 0, pending); err != nil {
			return nil, err
		}
		if i == 0 {
			count = len(pending)
		}
		return func() {
			for k, v := range pending {
				r.policies[k] = v
			}
		}, nil
	}); err != nil {
		return 0, err
	}

	if count == 0 {
		return 0, fmt.Errorf("%w in %s; keeping the existing policy set", errNoPoliciesFound, dir)
	}

	// Atomic swap - only hold lock briefly. In-flight evaluations keep the
	// replicas of the old set alive until they finish.
	e.mu.Lock()
	e.set = newSet
	e.mu.Unlock()

	e.logger.Info("policies reloaded atomically", zap.Int("count", count))
	return count, nil
}

// LoadPoliciesFromDir loads all policies from a directory and its
// subdirectories, adding to any policies already loaded. Like the reload
// path it fails closed: a policy that does not compile or validate, or a
// tree yielding zero policies, is an error and nothing is loaded.
func (e *Engine) LoadPoliciesFromDir(ctx context.Context, dir string) error {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()

	loaded := 0
	// Two-phase so a failure partway through leaves every replica identical.
	err := e.set.mutateAll(func(i int, r *policyReplica) (func(), error) {
		pending := make(map[string]*CompiledPolicy)
		if err := e.loadDirIntoReplica(ctx, dir, r, i != 0, pending); err != nil {
			return nil, err
		}
		if i == 0 {
			loaded = len(pending)
		}
		return func() {
			for k, v := range pending {
				r.policies[k] = v
			}
		}, nil
	})
	if err != nil {
		return err
	}
	if loaded == 0 {
		return fmt.Errorf("%w in %s", errNoPoliciesFound, dir)
	}
	return nil
}

// loadDirIntoReplica loads policies from dir (and its subdirectories) into a
// replica, compiling everything with the replica's own context. When quiet is
// true, logs and metrics are suppressed — used when replaying the same load
// onto the remaining replicas of a set.
// A directory that simply contains no policy documents (errNoPoliciesFound)
// keeps the scan going — shared-definition packages and test fixtures are
// legitimate. Every other error (a policy that fails to compile or validate)
// aborts the load: skipping a broken policy and continuing would deploy a
// partial policy set that looks healthy.
func (e *Engine) loadDirIntoReplica(ctx context.Context, dir string, r *policyReplica, quiet bool, pending map[string]*CompiledPolicy) error {
	// Load from the directory itself when it has CUE files of its own; a
	// root that only holds subdirectories is not an error.
	if hasCue, _ := e.hasCueFiles(dir); hasCue {
		if err := e.loadSingleDirIntoReplica(dir, r, quiet, pending); err != nil {
			if !errors.Is(err, errNoPoliciesFound) {
				return err
			}
			if !quiet {
				e.logger.Debug("no policies in root, scanning subdirectories", zap.String("dir", dir))
			}
		}
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

		// Skip hidden directories and common non-policy directories
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "cue.mod" {
			continue
		}

		subdir := filepath.Join(dir, name)

		hasCueFiles, _ := e.hasCueFiles(subdir)
		if hasCueFiles {
			if err := e.loadSingleDirIntoReplica(subdir, r, quiet, pending); err != nil {
				if !errors.Is(err, errNoPoliciesFound) {
					return err
				}
				if !quiet {
					e.logger.Debug("no policies in subdirectory", zap.String("dir", subdir))
				}
			}
		} else {
			// Recursively check deeper directories
			if err := e.loadDirIntoReplica(ctx, subdir, r, quiet, pending); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadSingleDirIntoReplica loads policies from a single directory (non-recursive)
// into a replica using the replica's context.
func (e *Engine) loadSingleDirIntoReplica(dir string, r *policyReplica, quiet bool, pending map[string]*CompiledPolicy) error {
	keys, err := e.loadInstancesIntoReplica([]string{"."}, dir, r, quiet, pending)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w in %s", errNoPoliciesFound, dir)
	}
	return nil
}

// loadInstancesIntoReplica compiles the given CUE package/file args (resolved
// relative to dir) in a replica's context, staging the results into pending
// rather than publishing them to r.policies. It returns the namespace/name
// keys of the policies loaded.
//
// Staging is what lets callers make a load atomic across replicas: nothing is
// visible to evaluations until every replica has compiled successfully.
func (e *Engine) loadInstancesIntoReplica(args []string, dir string, r *policyReplica, quiet bool, pending map[string]*CompiledPolicy) ([]string, error) {
	cfg := &load.Config{
		Dir: dir,
	}

	instances := load.Instances(args, cfg)
	var keys []string

	// Track namespaces that got policies loaded for metrics
	namespaceCounts := make(map[string]int)

	for _, inst := range instances {
		if inst.Err != nil {
			if !quiet {
				e.observability().Metrics().RecordPolicyLoadError("", dir, "compilation")
			}
			return nil, fmt.Errorf("loading instance: %w", inst.Err)
		}

		val := r.ctx.BuildInstance(inst)
		if val.Err() != nil {
			if !quiet {
				e.observability().Metrics().RecordPolicyLoadError("", dir, "compilation")
			}
			return nil, fmt.Errorf("building instance: %w", val.Err())
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

			// Unify with the schema before compiling — the directory loader is
			// the production path, and an unvalidated load here would accept
			// policies that `garmr validate` rejects. A failure aborts the
			// whole load rather than skipping the policy: silently deploying
			// a partial policy set is the outage this loader must prevent.
			unified := fieldVal.Unify(r.schema.LookupPath(cue.ParsePath("#Policy")))
			if unified.Err() != nil {
				if !quiet {
					e.observability().Metrics().RecordPolicyLoadError(name, ns, "schema")
				}
				return nil, fmt.Errorf("policy %s/%s in %s failed schema validation: %v", ns, name, dir, unified.Err())
			}

			compiled, err := e.compilePolicy(unified, name, ns)
			if err != nil {
				if !quiet {
					e.observability().Metrics().RecordPolicyLoadError(name, ns, "compilation")
				}
				return nil, fmt.Errorf("policy %s/%s in %s failed to compile: %w", ns, name, dir, err)
			}

			hash, err := canonicalPolicyHash(unified)
			if err != nil {
				return nil, fmt.Errorf("policy %s/%s in %s could not be hashed: %w", ns, name, dir, err)
			}
			compiled.Hash = hash
			compiled.LoadedAt = time.Now()
			key := policyKey(ns, name)
			pending[key] = compiled
			keys = append(keys, key)
			namespaceCounts[ns]++

			if !quiet {
				e.logger.Info("loaded policy from directory",
					zap.String("name", name),
					zap.String("namespace", ns),
				)
			}
		}
	}

	// Record loaded policy counts per namespace
	if !quiet {
		for ns, count := range namespaceCounts {
			e.observability().Metrics().SetPoliciesLoaded(ns, count)
		}
	}

	return keys, nil
}

// LoadPoliciesFromFile loads every policy declared in a single CUE file,
// adding to any policies already loaded. It returns the namespace/name keys
// of the policies the file declared.
func (e *Engine) LoadPoliciesFromFile(ctx context.Context, path string) ([]string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", path, err)
	}

	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()

	var keys []string
	err = e.set.mutateAll(func(i int, r *policyReplica) (func(), error) {
		pending := make(map[string]*CompiledPolicy)
		loaded, err := e.loadInstancesIntoReplica(
			[]string{"./" + filepath.Base(abs)}, filepath.Dir(abs), r, i != 0, pending)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			keys = loaded
		}
		return func() {
			for k, v := range pending {
				r.policies[k] = v
			}
		}, nil
	})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no policies found in %s", path)
	}
	return keys, nil
}

// Validate validates policy source without loading it. It accepts both a
// bare policy document (as used by LoadPolicy) and the on-disk file format
// where one or more policies are declared as named top-level fields (as used
// by the directory loader). It uses a throwaway CUE context so concurrent
// validations never share evaluator state.
func (e *Engine) Validate(source string) ([]ValidationError, []ValidationError) {
	vctx := cuecontext.New()

	schema := vctx.CompileString(policySchemaSource)
	if schema.Err() != nil {
		return []ValidationError{{
			Message: schema.Err().Error(),
			Code:    "SCHEMA_ERROR",
		}}, nil
	}

	val := vctx.CompileString(source)
	if val.Err() != nil {
		return []ValidationError{{
			Message: val.Err().Error(),
			Code:    "PARSE_ERROR",
		}}, nil
	}

	// Collect policy documents: the value itself if it is a bare policy,
	// otherwise every top-level field declaring kind: "Policy".
	var candidates []cue.Value
	if val.LookupPath(cue.ParsePath("kind")).Exists() {
		candidates = append(candidates, val)
	} else {
		iter, _ := val.Fields()
		for iter.Next() {
			fieldVal := iter.Value()
			kindVal := fieldVal.LookupPath(cue.ParsePath("kind"))
			if !kindVal.Exists() {
				continue
			}
			if kind, _ := kindVal.String(); kind == "Policy" {
				candidates = append(candidates, fieldVal)
			}
		}
	}

	if len(candidates) == 0 {
		return []ValidationError{{
			Message: "no Policy documents found (expected kind: \"Policy\")",
			Code:    "SCHEMA_ERROR",
		}}, nil
	}

	var errs []ValidationError
	schemaPolicy := schema.LookupPath(cue.ParsePath("#Policy"))
	for _, candidate := range candidates {
		if unified := candidate.Unify(schemaPolicy); unified.Err() != nil {
			errs = append(errs, ValidationError{
				Message: unified.Err().Error(),
				Code:    "SCHEMA_ERROR",
			})
		}
	}

	return errs, nil
}

// PolicySetDigest returns a deterministic digest of the loaded policy set:
// sha256 over the sorted "namespace/name:hash" lines of every policy. Two
// processes hold identical policy content iff their digests match, so a CI
// pipeline can compare the digest of its git checkout (via `garmr policy
// digest`) with the digest a running server reports.
func (e *Engine) PolicySetDigest() string {
	set := e.currentSet()
	rep := set.get()
	defer set.put(rep)

	lines := make([]string, 0, len(rep.policies))
	for k, p := range rep.policies {
		lines = append(lines, k+":"+p.Hash)
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, line := range lines {
		h.Write([]byte(line))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// policyKey creates a unique key for a policy.
func policyKey(namespace, name string) string {
	if namespace == "" {
		namespace = "default"
	}
	return namespace + "/" + name
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

	count, err := e.ReloadPoliciesFromDir(ctx, tempDir)
	if err != nil {
		return 0, err
	}

	e.logger.Info("policies reloaded from backend",
		zap.String("backend", backend.Type()),
		zap.Int("count", count),
	)
	return count, nil
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
		// Containment check before touching the filesystem. A backend key
		// containing ".." or an absolute path would otherwise write outside
		// the temp directory as the server user. Fail the whole load rather
		// than skipping the file: a partially staged policy set is exactly
		// the silent-pass that requireMatch exists to prevent.
		rel := filepath.FromSlash(file.Path)
		if !filepath.IsLocal(rel) {
			cleanup()
			return "", func() {}, fmt.Errorf("backend %s returned unsafe path %q", backend.Type(), file.Path)
		}

		destPath := filepath.Join(tempDir, rel)
		if !storage.WithinRoot(tempDir, destPath) {
			cleanup()
			return "", func() {}, fmt.Errorf("backend %s returned path %q that escapes the staging directory", backend.Type(), file.Path)
		}

		content, err := backend.Get(ctx, file.Path)
		if err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("reading %s from backend: %w", file.Path, err)
		}

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
