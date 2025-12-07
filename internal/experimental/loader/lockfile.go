// internal/loader/lockfile.go
// Lock file schema and utilities
package loader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// LockFile represents a policy lock file for version control.
// Lock files enable GitOps workflows where policy changes are explicit.
type LockFile struct {
	// Schema version for lock file format
	SchemaVersion string `json:"schemaVersion"`

	// SHA256 checksum of the policy file content
	Checksum string `json:"checksum"`

	// Semantic version of the policy (optional, for human reference)
	Version string `json:"version,omitempty"`

	// When the lock file was generated
	UpdatedAt time.Time `json:"updatedAt"`

	// Who generated the lock file (from git config or system user)
	UpdatedBy string `json:"updatedBy,omitempty"`

	// Source file information
	Source LockFileSource `json:"source"`

	// Optional metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// LockFileSource contains information about the source policy file.
type LockFileSource struct {
	// Original file path (relative to policy root)
	File string `json:"file"`

	// File size in bytes
	Size int64 `json:"size"`

	// Number of rules in the policy (for quick reference)
	RuleCount int `json:"rules,omitempty"`

	// Number of policies (for policy sets)
	PolicyCount int `json:"policies,omitempty"`

	// Policy names contained in the file
	PolicyNames []string `json:"policyNames,omitempty"`
}

const (
	// LockFileSchemaVersion is the current lock file schema version
	LockFileSchemaVersion = "1.0"

	// DefaultLockExtension is the default lock file extension
	DefaultLockExtension = ".lock"
)

// GenerateLockFile creates a lock file for a policy file.
func GenerateLockFile(policyPath string, opts LockFileOptions) (*LockFile, error) {
	// Read policy file
	content, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	// Get file info
	info, err := os.Stat(policyPath)
	if err != nil {
		return nil, fmt.Errorf("stat policy file: %w", err)
	}

	// Compute checksum
	hash := sha256.Sum256(content)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	// Determine updatedBy
	updatedBy := opts.UpdatedBy
	if updatedBy == "" {
		updatedBy = getCurrentUser()
	}

	// Count rules if parser provided
	ruleCount := 0
	var policyNames []string
	if opts.PolicyParser != nil {
		ruleCount, policyNames, _ = opts.PolicyParser(content)
	}

	lock := &LockFile{
		SchemaVersion: LockFileSchemaVersion,
		Checksum:      checksum,
		Version:       opts.Version,
		UpdatedAt:     time.Now().UTC(),
		UpdatedBy:     updatedBy,
		Source: LockFileSource{
			File:        filepath.Base(policyPath),
			Size:        info.Size(),
			RuleCount:   ruleCount,
			PolicyNames: policyNames,
		},
		Metadata: opts.Metadata,
	}

	return lock, nil
}

// LockFileOptions configures lock file generation.
type LockFileOptions struct {
	// Version to embed in lock file (e.g., "2.5.1")
	Version string

	// Who is generating the lock file
	UpdatedBy string

	// Additional metadata
	Metadata map[string]string

	// Optional parser to extract rule count and policy names
	PolicyParser func(content []byte) (ruleCount int, policyNames []string, err error)
}

// WriteLockFile writes a lock file to disk.
func WriteLockFile(lock *LockFile, policyPath string) error {
	lockPath := policyPath + DefaultLockExtension

	content, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling lock file: %w", err)
	}

	// Add trailing newline for git friendliness
	content = append(content, '\n')

	if err := os.WriteFile(lockPath, content, 0644); err != nil {
		return fmt.Errorf("writing lock file: %w", err)
	}

	return nil
}

// ReadLockFile reads a lock file from disk.
func ReadLockFile(lockPath string) (*LockFile, error) {
	content, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	var lock LockFile
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parsing lock file: %w", err)
	}

	return &lock, nil
}

// ValidateLockFile checks if a policy file matches its lock file.
func ValidateLockFile(policyPath string) (*LockFileValidation, error) {
	lockPath := policyPath + DefaultLockExtension

	// Read lock file
	lock, err := ReadLockFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &LockFileValidation{
				Valid:   false,
				Reason:  "lock file not found",
				Details: "Run 'q policy lock' to generate",
			}, nil
		}
		return nil, err
	}

	// Read and hash policy file
	content, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(content)
	currentChecksum := "sha256:" + hex.EncodeToString(hash[:])

	// Compare checksums
	if currentChecksum != lock.Checksum {
		return &LockFileValidation{
			Valid:            false,
			Reason:           "checksum mismatch",
			ExpectedChecksum: lock.Checksum,
			ActualChecksum:   currentChecksum,
			LockVersion:      lock.Version,
			LockUpdatedAt:    lock.UpdatedAt,
			Details:          "Policy file has been modified. Run 'q policy lock' to update.",
		}, nil
	}

	return &LockFileValidation{
		Valid:         true,
		LockVersion:   lock.Version,
		LockUpdatedAt: lock.UpdatedAt,
	}, nil
}

// LockFileValidation contains the result of validating a lock file.
type LockFileValidation struct {
	Valid            bool
	Reason           string
	ExpectedChecksum string
	ActualChecksum   string
	LockVersion      string
	LockUpdatedAt    time.Time
	Details          string
}

// getCurrentUser returns the current user identifier.
func getCurrentUser() string {
	// Try git config first
	if email := getGitEmail(); email != "" {
		return email
	}

	// Fall back to system user
	if u, err := user.Current(); err == nil {
		return u.Username
	}

	return "unknown"
}

// getGitEmail attempts to get the user's email from git config.
func getGitEmail() string {
	// In real implementation, would exec: git config user.email
	// Simplified here
	return ""
}

// OnDemandChecker handles on-demand policy reload checks.
type OnDemandChecker struct {
	// Cache of known checksums: path -> checksum
	checksums map[string]string

	// Lock file extension
	lockExt string
}

// NewOnDemandChecker creates a new on-demand checker.
func NewOnDemandChecker(lockExt string) *OnDemandChecker {
	if lockExt == "" {
		lockExt = DefaultLockExtension
	}
	return &OnDemandChecker{
		checksums: make(map[string]string),
		lockExt:   lockExt,
	}
}

// CheckResult contains the result of an on-demand check.
type CheckResult struct {
	// Whether the policy needs to be reloaded
	NeedsReload bool

	// Reason for reload (if needed)
	Reason string

	// Lock file information (if available)
	LockVersion   string
	LockUpdatedAt time.Time
	LockUpdatedBy string
}

// Check determines if a policy needs to be reloaded.
// This is called before each evaluation in on-demand mode.
func (c *OnDemandChecker) Check(policyPath string) (*CheckResult, error) {
	lockPath := policyPath + c.lockExt

	// Read lock file
	lock, err := ReadLockFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No lock file - check if we have a cached version
			if _, ok := c.checksums[policyPath]; !ok {
				return &CheckResult{
					NeedsReload: true,
					Reason:      "no cached version",
				}, nil
			}
			// Have cached version, no lock file - use cached
			return &CheckResult{NeedsReload: false}, nil
		}
		return nil, err
	}

	// Compare lock checksum with cached checksum
	cachedChecksum, hasCached := c.checksums[policyPath]

	if !hasCached {
		// No cached version - need to load
		return &CheckResult{
			NeedsReload:   true,
			Reason:        "no cached version",
			LockVersion:   lock.Version,
			LockUpdatedAt: lock.UpdatedAt,
			LockUpdatedBy: lock.UpdatedBy,
		}, nil
	}

	if cachedChecksum != lock.Checksum {
		// Checksum mismatch - need to reload
		return &CheckResult{
			NeedsReload:   true,
			Reason:        "lock file checksum changed",
			LockVersion:   lock.Version,
			LockUpdatedAt: lock.UpdatedAt,
			LockUpdatedBy: lock.UpdatedBy,
		}, nil
	}

	// Checksums match - no reload needed
	return &CheckResult{
		NeedsReload:   false,
		LockVersion:   lock.Version,
		LockUpdatedAt: lock.UpdatedAt,
	}, nil
}

// UpdateCache updates the cached checksum after a successful reload.
func (c *OnDemandChecker) UpdateCache(policyPath, checksum string) {
	c.checksums[policyPath] = checksum
}

// InvalidateCache removes a policy from the cache.
func (c *OnDemandChecker) InvalidateCache(policyPath string) {
	delete(c.checksums, policyPath)
}
