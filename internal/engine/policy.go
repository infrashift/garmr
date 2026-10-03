package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/load"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/storage"
)

// ListPolicies returns the loaded policies, sorted by namespace/name. The
// returned values are shared and must be treated as read-only.
func (e *Engine) ListPolicies(namespace string) []*CompiledPolicy {
	var result []*CompiledPolicy
	for _, p := range e.set.Load().all {
		if namespace == "" || p.Namespace == namespace {
			result = append(result, p)
		}
	}
	return result
}

// GetPolicy returns a specific policy (read-only).
func (e *Engine) GetPolicy(namespace, name string) (*CompiledPolicy, error) {
	if p, ok := e.set.Load().policies[policyKey(namespace, name)]; ok {
		return p, nil
	}
	return nil, ErrPolicyNotFound
}

// errNoPoliciesFound marks a directory that yielded zero policy documents.
// The walker treats it as "keep scanning"; every other load error is a real
// failure and aborts the load.
var errNoPoliciesFound = errors.New("no policies found")

// mutate builds the policies staged by build in a fresh CUE context and
// publishes a new set: the staged policies alone when replace is set,
// otherwise merged over the current set. Nothing is published if build
// fails, so a failed load never leaves a partial set.
func (e *Engine) mutate(replace bool, build func(cctx *cue.Context, schema cue.Value, pending map[string]*CompiledPolicy) error) error {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()

	cctx, schema, err := newLoadContext()
	if err != nil {
		return err
	}
	pending := make(map[string]*CompiledPolicy)
	if err := build(cctx, schema, pending); err != nil {
		return err
	}

	next := pending
	if !replace {
		next = maps.Clone(e.set.Load().policies)
		maps.Copy(next, pending)
	}
	e.publish(next)
	return nil
}

// publish swaps in a new set. Callers hold loadMu.
func (e *Engine) publish(policies map[string]*CompiledPolicy) {
	e.set.Store(newPolicySet(policies))
	e.observability().Metrics().SetPoliciesLoaded(namespaceCounts(policies))
}

// DeletePolicy removes a policy.
func (e *Engine) DeletePolicy(namespace, name string) bool {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()

	key := policyKey(namespace, name)
	cur := e.set.Load().policies
	if _, ok := cur[key]; !ok {
		return false
	}
	next := maps.Clone(cur)
	delete(next, key)
	e.publish(next)
	return true
}

// namespaceCounts returns the per-namespace counts published as the
// policies_loaded gauge snapshot.
func namespaceCounts(policies map[string]*CompiledPolicy) map[string]int {
	counts := make(map[string]int, len(policies))
	for _, p := range policies {
		counts[p.Namespace]++
	}
	return counts
}

// ReloadPoliciesFromDir atomically replaces the loaded set with the policies
// in a directory tree. In-flight evaluations finish against the set they
// started with.
//
// Any failure — a policy that does not compile or validate, or a directory
// tree yielding zero policies — leaves the existing set live and returns the
// error. Swapping in an empty or partial set on a bad deploy would silently
// deny (or skip) everything, which is an outage a 200 response would hide.
func (e *Engine) ReloadPoliciesFromDir(ctx context.Context, dir string) (int, error) {
	count := 0
	err := e.mutate(true, func(cctx *cue.Context, schema cue.Value, pending map[string]*CompiledPolicy) error {
		if err := e.loadDir(cctx, schema, dir, pending); err != nil {
			return err
		}
		if count = len(pending); count == 0 {
			return fmt.Errorf("%w in %s; keeping the existing policy set", errNoPoliciesFound, dir)
		}
		return nil
	})
	e.observability().Metrics().RecordPolicyReload(err == nil)
	if err != nil {
		return 0, err
	}
	e.logger.Info("policies reloaded atomically", zap.Int("count", count))
	return count, nil
}

// LoadPoliciesFromDir loads all policies from a directory and its
// subdirectories, adding to any policies already loaded. Like the reload
// path it fails closed: a policy that does not compile or validate, or a
// tree yielding zero policies, is an error and nothing is loaded.
func (e *Engine) LoadPoliciesFromDir(ctx context.Context, dir string) error {
	return e.mutate(false, func(cctx *cue.Context, schema cue.Value, pending map[string]*CompiledPolicy) error {
		if err := e.loadDir(cctx, schema, dir, pending); err != nil {
			return err
		}
		if len(pending) == 0 {
			return fmt.Errorf("%w in %s", errNoPoliciesFound, dir)
		}
		return nil
	})
}

// loadDir loads policies from dir and every subdirectory beneath it into
// pending.
//
// A directory that simply contains no policy documents (errNoPoliciesFound)
// keeps the scan going — shared-definition packages and test fixtures are
// legitimate. Every other error (a policy that fails to compile or validate)
// aborts the load: skipping a broken policy and continuing would deploy a
// partial policy set that looks healthy.
//
// Every directory is loaded as its own CUE package and the walk continues
// beneath it. It used to stop descending as soon as a directory had .cue files
// of its own, so given policies/security/{base.cue,k8s/pod.cue} the k8s/
// subtree was never visited: pod.cue silently went unenforced, the load
// *succeeded* because base.cue satisfied the non-empty check, and the server
// came up reporting ready.
func (e *Engine) loadDir(cctx *cue.Context, schema cue.Value, dir string, pending map[string]*CompiledPolicy) error {
	// Load from the directory itself when it has CUE files of its own; a
	// directory that only holds subdirectories is not an error.
	if hasCue, _ := hasCueFiles(dir); hasCue {
		keys, err := e.loadInstances(cctx, schema, []string{"."}, dir, pending)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			e.logger.Debug("no policy documents here, continuing scan", zap.String("dir", dir))
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Skip hidden directories and common non-policy directories.
		//
		// testdata is skipped to match the storage backend's default exclude
		// patterns (internal/storage/filesystem.go), which /health/deep's
		// List() consults: otherwise it would report fixture files as absent
		// while the loader compiled and enforced them. (*_test.cue needs no
		// handling here: CUE itself excludes test files unless
		// load.Config.Tests is set, which it is not.)
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" ||
			name == "cue.mod" || name == "testdata" {
			continue
		}

		if err := e.loadDir(cctx, schema, filepath.Join(dir, name), pending); err != nil {
			return err
		}
	}

	return nil
}

// loadInstances compiles the given CUE package/file args (resolved relative
// to dir), staging every policy document found into pending. It returns the
// namespace/name keys of the policies loaded.
func (e *Engine) loadInstances(cctx *cue.Context, schema cue.Value, args []string, dir string, pending map[string]*CompiledPolicy) ([]string, error) {
	instances := load.Instances(args, &load.Config{Dir: dir})
	var keys []string

	for _, inst := range instances {
		if inst.Err != nil {
			e.observability().Metrics().RecordPolicyLoadError("", dir, "compilation")
			return nil, fmt.Errorf("loading instance: %w", inst.Err)
		}

		val := cctx.BuildInstance(inst)
		if val.Err() != nil {
			e.observability().Metrics().RecordPolicyLoadError("", dir, "compilation")
			return nil, fmt.Errorf("building instance: %w", val.Err())
		}

		iter, _ := val.Fields()
		for iter.Next() {
			fieldVal := iter.Value()

			kindVal := fieldVal.LookupPath(cue.ParsePath("kind"))
			if kind, _ := kindVal.String(); kind != "Policy" {
				continue
			}

			name, _ := fieldVal.LookupPath(cue.ParsePath("metadata.name")).String()
			ns := "default"
			if nsVal := fieldVal.LookupPath(cue.ParsePath("metadata.namespace")); nsVal.Exists() {
				ns, _ = nsVal.String()
			}

			// Unify with the schema before compiling — the directory loader is
			// the production path, and an unvalidated load here would accept
			// policies that `garmr validate` rejects. A failure aborts the
			// whole load rather than skipping the policy: silently deploying
			// a partial policy set is the outage this loader must prevent.
			unified := fieldVal.Unify(schema)
			if unified.Err() != nil {
				e.observability().Metrics().RecordPolicyLoadError(name, ns, "schema")
				return nil, fmt.Errorf("policy %s/%s in %s failed schema validation: %w", ns, name, dir, unified.Err())
			}

			compiled, err := e.compilePolicy(unified, name, ns)
			if err != nil {
				e.observability().Metrics().RecordPolicyLoadError(name, ns, "compilation")
				return nil, fmt.Errorf("policy %s/%s in %s failed to compile: %w", ns, name, dir, err)
			}
			compiled.Source = dir

			// Two documents declaring the same policy used to load with the
			// last one silently winning, so which rules were enforced
			// depended on directory walk order.
			key := policyKey(ns, name)
			if prev, ok := pending[key]; ok {
				return nil, fmt.Errorf("policy %s is declared twice (in %s and %s)", key, prev.Source, dir)
			}
			pending[key] = compiled
			keys = append(keys, key)

			e.logger.Info("loaded policy from directory",
				zap.String("name", name),
				zap.String("namespace", ns),
			)
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

	var keys []string
	err = e.mutate(false, func(cctx *cue.Context, schema cue.Value, pending map[string]*CompiledPolicy) error {
		var loadErr error
		keys, loadErr = e.loadInstances(cctx, schema, []string{"./" + filepath.Base(abs)}, filepath.Dir(abs), pending)
		if loadErr != nil {
			return loadErr
		}
		if len(keys) == 0 {
			return fmt.Errorf("no policies found in %s", path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// Validate validates policy source without loading it. It accepts both a
// bare policy document (as used by LoadPolicy) and the on-disk file format
// where one or more policies are declared as named top-level fields (as used
// by the directory loader), and applies the same schema and compile checks
// as the loader. It uses a throwaway CUE context so concurrent validations
// never share evaluator state.
func (e *Engine) Validate(source string) ([]ValidationError, []ValidationError) {
	vctx, schemaPolicy, err := newLoadContext()
	if err != nil {
		return []ValidationError{{
			Message: err.Error(),
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
	for _, candidate := range candidates {
		unified := candidate.Unify(schemaPolicy)
		if unified.Err() != nil {
			errs = append(errs, ValidationError{
				Message: unified.Err().Error(),
				Code:    "SCHEMA_ERROR",
			})
			continue
		}
		// Run the loader's compile step too: a policy that passes the schema
		// but that the server would refuse to load is not valid.
		if _, err := e.compilePolicy(unified, "", ""); err != nil {
			errs = append(errs, ValidationError{
				Message: err.Error(),
				Code:    "COMPILE_ERROR",
			})
		}
	}

	return errs, nil
}

// setSnapshot identifies a policy set's content.
type setSnapshot struct {
	// Count is the number of loaded policies.
	Count int
	// Digest identifies the set's content; see PolicySetDigest.
	Digest string
}

// snapshotOf derives a snapshot from a policy map. A nil or empty map yields
// the digest of the empty set.
func snapshotOf(policies map[string]*CompiledPolicy) setSnapshot {
	lines := make([]string, 0, len(policies))
	for k, p := range policies {
		lines = append(lines, k+":"+p.Hash)
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, line := range lines {
		h.Write([]byte(line))
		h.Write([]byte{'\n'})
	}
	return setSnapshot{Count: len(policies), Digest: hex.EncodeToString(h.Sum(nil))}
}

// PolicyCount returns the number of loaded policies. It never blocks, so it
// is safe to call from a health probe.
func (e *Engine) PolicyCount() int {
	return e.set.Load().snap.Count
}

// PolicySetDigest returns a deterministic digest of the loaded policy set:
// sha256 over the sorted "namespace/name:hash" lines of every policy. Two
// processes hold identical policy content iff their digests match, so a CI
// pipeline can compare the digest of its git checkout (via `garmr policy
// digest`) with the digest a running server reports.
func (e *Engine) PolicySetDigest() string {
	return e.set.Load().snap.Digest
}

// policyKey creates a unique key for a policy.
func policyKey(namespace, name string) string {
	if namespace == "" {
		namespace = "default"
	}
	return namespace + "/" + name
}

// hasCueFiles checks if a directory contains .cue files
func hasCueFiles(dir string) (bool, error) {
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

// withBackendDir resolves a storage backend to an on-disk directory and
// calls fn on it: the filesystem backend's root is used directly (zero
// overhead), any other backend is staged into a temp directory first.
func (e *Engine) withBackendDir(ctx context.Context, backend storage.Backend, fn func(dir string) error) error {
	if fsBackend, ok := backend.(*storage.FilesystemBackend); ok {
		return fn(fsBackend.Root())
	}

	tempDir, cleanup, err := e.stageBackendFiles(ctx, backend)
	if err != nil {
		return fmt.Errorf("staging backend files: %w", err)
	}
	defer cleanup()

	return fn(tempDir)
}

// LoadPoliciesFromBackend loads all policies from a storage backend.
func (e *Engine) LoadPoliciesFromBackend(ctx context.Context, backend storage.Backend) error {
	return e.withBackendDir(ctx, backend, func(dir string) error {
		return e.LoadPoliciesFromDir(ctx, dir)
	})
}

// ReloadPoliciesFromBackend atomically reloads all policies from a storage backend.
// This is safe to call while evaluations are in progress.
func (e *Engine) ReloadPoliciesFromBackend(ctx context.Context, backend storage.Backend) (int, error) {
	var count int
	err := e.withBackendDir(ctx, backend, func(dir string) error {
		var reloadErr error
		count, reloadErr = e.ReloadPoliciesFromDir(ctx, dir)
		return reloadErr
	})
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
