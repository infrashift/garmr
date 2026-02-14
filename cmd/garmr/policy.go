// cmd/garmr/policy.go
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/infrashift/garmr/internal/client"
)

// validateCmd validates policy files
var validateCmd = &cobra.Command{
	Use:   "validate [files...]",
	Short: "Validate policy files",
	Long: `Validate CUE policy files for syntax and schema compliance.

Examples:
  # Validate a single policy
  garmr validate policy.cue

  # Validate multiple policies
  garmr validate policies/*.cue

  # Validate and show warnings
  garmr validate --warn policy.cue`,
	Args: cobra.MinimumNArgs(1),
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().Bool("warn", false, "show warnings")
	validateCmd.Flags().Bool("strict", false, "fail on warnings")
}

func runValidate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}
	serverAddr = strings.Replace(serverAddr, ":9090", ":8080", 1)

	cfg := client.Config{
		Address: serverAddr,
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer c.Close()

	showWarn, _ := cmd.Flags().GetBool("warn")
	strict, _ := cmd.Flags().GetBool("strict")
	hasErrors := false

	for _, file := range args {
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
			hasErrors = true
			continue
		}

		result, err := c.Validate(ctx, string(content))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error validating %s: %v\n", file, err)
			hasErrors = true
			continue
		}

		if result.Valid {
			fmt.Printf("✓ %s: valid\n", file)
		} else {
			fmt.Printf("✗ %s: invalid\n", file)
			for _, e := range result.Errors {
				loc := ""
				if e.Line > 0 {
					loc = fmt.Sprintf(":%d:%d", e.Line, e.Column)
				}
				fmt.Printf("  error%s: %s\n", loc, e.Message)
			}
			hasErrors = true
		}

		if showWarn && len(result.Warnings) > 0 {
			for _, w := range result.Warnings {
				fmt.Printf("  warning: %s\n", w.Message)
			}
			if strict {
				hasErrors = true
			}
		}
	}

	if hasErrors {
		os.Exit(1)
	}

	return nil
}

// policyCmd is the parent command for policy management
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage policies",
	Long:  `Commands for listing, viewing, and managing policies.`,
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded policies",
	Long: `List all policies loaded in the Garmr server.

Examples:
  # List all policies
  garmr policy list

  # List policies in a namespace
  garmr policy list -n security

  # Output as JSON
  garmr policy list -o json`,
	RunE: runPolicyList,
}

var policyGetCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "Get policy details",
	Long: `Get details of a specific policy.

Examples:
  garmr policy get no-privileged-containers
  garmr policy get no-privileged-containers -n security`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyGet,
}

var policyPushCmd = &cobra.Command{
	Use:   "push [file]",
	Short: "Push a policy to the server",
	Long: `Push a policy file to the Garmr server.

Examples:
  # Push a policy
  garmr policy push policy.cue

  # Push with explicit name and namespace
  garmr policy push policy.cue --name my-policy --namespace security

  # Validate only (don't actually push)
  garmr policy push policy.cue --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyPush,
}

var policyDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a policy",
	Long: `Delete a policy from the Garmr server.

Examples:
  garmr policy delete my-policy
  garmr policy delete my-policy -n security`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyDelete,
}

var policyReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload policies from disk",
	Long: `Trigger a reload of policies from the configured directory.

Examples:
  garmr policy reload
  garmr policy reload --force`,
	RunE: runPolicyReload,
}

func init() {
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyGetCmd)
	policyCmd.AddCommand(policyPushCmd)
	policyCmd.AddCommand(policyDeleteCmd)
	policyCmd.AddCommand(policyReloadCmd)
	policyCmd.AddCommand(policyLockCmd)
	policyCmd.AddCommand(policyValidateLockCmd)
	policyCmd.AddCommand(policyDiffCmd)

	// List flags
	policyListCmd.Flags().StringP("namespace", "n", "", "filter by namespace")
	policyListCmd.Flags().StringSlice("label", nil, "filter by labels (key=value)")

	// Get flags
	policyGetCmd.Flags().StringP("namespace", "n", "default", "policy namespace")

	// Push flags
	policyPushCmd.Flags().StringP("name", "", "", "policy name (default: from file)")
	policyPushCmd.Flags().StringP("namespace", "n", "default", "policy namespace")
	policyPushCmd.Flags().Bool("dry-run", false, "validate only")

	// Delete flags
	policyDeleteCmd.Flags().StringP("namespace", "n", "default", "policy namespace")
	policyDeleteCmd.Flags().Bool("force", false, "skip confirmation")

	// Reload flags
	policyReloadCmd.Flags().Bool("force", false, "force reload even if unchanged")

	// Lock flags
	policyLockCmd.Flags().String("version", "", "version to embed in lock file")
	policyLockCmd.Flags().Bool("recursive", false, "process directories recursively")
	policyLockCmd.Flags().String("updated-by", "", "override updatedBy field")
}

// policyLockCmd generates lock files for GitOps workflows
var policyLockCmd = &cobra.Command{
	Use:   "lock <policy-file> [policy-file...]",
	Short: "Generate lock files for policy files",
	Long: `Generate lock files for one or more policy files.

Lock files contain a SHA256 checksum of the policy content and enable
the on-demand reload strategy for GitOps workflows. When Garmr starts with
on-demand mode, it compares the lock file checksum with the cached
policy checksum to determine if a reload is needed.

Examples:
  # Generate lock file for a single policy
  garmr policy lock policies/release/prod-release.cue

  # Generate with explicit version
  garmr policy lock policies/release/prod-release.cue --version 2.5.1

  # Generate lock files for all policies in a directory
  garmr policy lock --recursive policies/release/

Lock File Format:
  {
    "schemaVersion": "1.0",
    "checksum": "sha256:e3b0c44...",
    "version": "2.5.1",
    "updatedAt": "2024-12-06T15:30:00Z",
    "updatedBy": "jane@example.com",
    "source": {
      "file": "prod-release.cue",
      "size": 15234
    }
  }

GitOps Workflow:
  1. Edit policy file
  2. Run 'garmr policy lock <file>'
  3. Commit both policy and .lock file
  4. GitOps controller syncs to cluster
  5. Garmr detects lock file change, reloads policy`,
	Args: cobra.MinimumNArgs(1),
	RunE: runPolicyLock,
}

// policyValidateLockCmd validates lock files match their policies
var policyValidateLockCmd = &cobra.Command{
	Use:   "validate-lock <policy-file> [policy-file...]",
	Short: "Validate policy lock files",
	Long: `Validate that lock files match their corresponding policy files.

This command is useful in CI/CD pipelines to ensure lock files
are up-to-date before deployment. It exits with code 1 if any
lock file is missing or has a mismatched checksum.

Examples:
  # Validate a single policy
  garmr policy validate-lock policies/release/prod-release.cue

  # Validate all policies (in CI)
  garmr policy validate-lock --recursive policies/ || exit 1`,
	Args: cobra.MinimumNArgs(1),
	RunE: runPolicyValidateLock,
}

// policyDiffCmd shows differences between policy and lock file
var policyDiffCmd = &cobra.Command{
	Use:   "diff <policy-file>",
	Short: "Compare policy with its lock file",
	Long: `Compare a policy file with its lock file and show status.

This helps understand what has changed since the lock file was generated.

Examples:
  garmr policy diff policies/release/prod-release.cue`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyDiff,
}

func runPolicyLock(cmd *cobra.Command, args []string) error {
	version, _ := cmd.Flags().GetString("version")
	recursive, _ := cmd.Flags().GetBool("recursive")
	updatedBy, _ := cmd.Flags().GetString("updated-by")

	var files []string
	for _, arg := range args {
		expanded, err := expandPolicyPaths(arg, recursive)
		if err != nil {
			return fmt.Errorf("expanding %s: %w", arg, err)
		}
		files = append(files, expanded...)
	}

	if len(files) == 0 {
		return fmt.Errorf("no policy files found")
	}

	var errors []error
	for _, file := range files {
		if err := generateLockFile(file, version, updatedBy); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d error(s):\n", len(errors))
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		return fmt.Errorf("lock generation failed")
	}

	return nil
}

func runPolicyValidateLock(cmd *cobra.Command, args []string) error {
	var files []string
	for _, arg := range args {
		expanded, err := expandPolicyPaths(arg, true)
		if err != nil {
			return fmt.Errorf("expanding %s: %w", arg, err)
		}
		files = append(files, expanded...)
	}

	if len(files) == 0 {
		return fmt.Errorf("no policy files found")
	}

	var errors []error
	for _, file := range files {
		if err := validateLockFileCmd(file); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d validation error(s)\n", len(errors))
		os.Exit(1)
	}

	fmt.Printf("\n✓ All %d lock files valid\n", len(files))
	return nil
}

func runPolicyDiff(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	lockPath := policyPath + ".lock"

	// Check if lock file exists
	lockInfo, err := os.Stat(lockPath)
	if os.IsNotExist(err) {
		fmt.Printf("Policy: %s\n", policyPath)
		fmt.Printf("Lock:   (not found)\n\n")
		fmt.Println("No lock file exists. Run 'garmr policy lock' to generate one.")
		return nil
	}

	// Read lock file
	lockContent, err := os.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading lock file: %w", err)
	}

	var lock struct {
		Checksum  string    `json:"checksum"`
		Version   string    `json:"version"`
		UpdatedAt time.Time `json:"updatedAt"`
		UpdatedBy string    `json:"updatedBy"`
		Source    struct {
			File string `json:"file"`
			Size int64  `json:"size"`
		} `json:"source"`
	}
	if err := json.Unmarshal(lockContent, &lock); err != nil {
		return fmt.Errorf("parsing lock file: %w", err)
	}

	// Compute current checksum
	content, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("reading policy: %w", err)
	}

	hash := sha256Sum(content)
	currentChecksum := "sha256:" + hash

	// Display comparison
	fmt.Printf("Policy:      %s\n", policyPath)
	fmt.Printf("Lock:        %s\n", lockPath)
	fmt.Println()
	fmt.Printf("Lock Version:     %s\n", lock.Version)
	fmt.Printf("Lock Updated:     %s\n", lock.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Lock Updated By:  %s\n", lock.UpdatedBy)
	fmt.Printf("Lock Size:        %d bytes\n", lock.Source.Size)
	fmt.Printf("Lock Modified:    %s\n", lockInfo.ModTime().Format("2006-01-02 15:04:05"))
	fmt.Println()

	if currentChecksum == lock.Checksum {
		fmt.Println("Status: ✓ IN SYNC")
		fmt.Printf("Checksum: %s\n", truncateHash(lock.Checksum))
	} else {
		fmt.Println("Status: ✗ OUT OF SYNC")
		fmt.Printf("Lock Checksum:    %s\n", truncateHash(lock.Checksum))
		fmt.Printf("Current Checksum: %s\n", truncateHash(currentChecksum))
		fmt.Println()
		fmt.Println("The policy has been modified since the lock file was generated.")
		fmt.Println("Run 'garmr policy lock' to update the lock file.")
	}

	return nil
}

func generateLockFile(policyPath, version, updatedBy string) error {
	content, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("%s: %w", policyPath, err)
	}

	info, err := os.Stat(policyPath)
	if err != nil {
		return fmt.Errorf("%s: %w", policyPath, err)
	}

	hash := sha256Sum(content)
	checksum := "sha256:" + hash

	if updatedBy == "" {
		if u, err := user.Current(); err == nil {
			updatedBy = u.Username
		}
	}

	lock := map[string]interface{}{
		"schemaVersion": "1.0",
		"checksum":      checksum,
		"updatedAt":     time.Now().UTC().Format(time.RFC3339),
		"updatedBy":     updatedBy,
		"source": map[string]interface{}{
			"file": filepath.Base(policyPath),
			"size": info.Size(),
		},
	}

	if version != "" {
		lock["version"] = version
	}

	lockContent, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	lockContent = append(lockContent, '\n')

	lockPath := policyPath + ".lock"
	if err := os.WriteFile(lockPath, lockContent, 0644); err != nil {
		return fmt.Errorf("writing lock file: %w", err)
	}

	fmt.Printf("✓ %s (checksum: %s)\n", filepath.Base(lockPath), truncateHash(checksum))
	return nil
}

func validateLockFileCmd(policyPath string) error {
	lockPath := policyPath + ".lock"

	// Read lock file
	lockContent, err := os.ReadFile(lockPath)
	if os.IsNotExist(err) {
		fmt.Printf("✗ %s: lock file not found\n", filepath.Base(policyPath))
		return fmt.Errorf("missing lock file")
	}
	if err != nil {
		return err
	}

	var lock struct {
		Checksum string `json:"checksum"`
		Version  string `json:"version"`
	}
	if err := json.Unmarshal(lockContent, &lock); err != nil {
		return fmt.Errorf("parsing lock file: %w", err)
	}

	// Compute current checksum
	content, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}

	currentChecksum := "sha256:" + sha256Sum(content)

	if currentChecksum != lock.Checksum {
		fmt.Printf("✗ %s: checksum mismatch (version: %s)\n", filepath.Base(policyPath), lock.Version)
		return fmt.Errorf("checksum mismatch")
	}

	fmt.Printf("✓ %s (version: %s)\n", filepath.Base(policyPath), lock.Version)
	return nil
}

func expandPolicyPaths(path string, recursive bool) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		// Try as glob
		matches, _ := filepath.Glob(path)
		if len(matches) > 0 {
			var result []string
			for _, m := range matches {
				if strings.HasSuffix(m, ".cue") && !strings.HasSuffix(m, ".lock") {
					result = append(result, m)
				}
			}
			return result, nil
		}
		return nil, err
	}

	if !info.IsDir() {
		if strings.HasSuffix(path, ".cue") {
			return []string{path}, nil
		}
		return nil, nil
	}

	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if !recursive && p != path {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".cue") && !strings.HasSuffix(p, ".lock") {
			files = append(files, p)
		}
		return nil
	})

	return files, err
}

func sha256Sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func truncateHash(hash string) string {
	if len(hash) > 24 {
		return hash[:24] + "..."
	}
	return hash
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}
	serverAddr = strings.Replace(serverAddr, ":9090", ":8080", 1)

	cfg := client.Config{
		Address: serverAddr,
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer c.Close()

	namespace, _ := cmd.Flags().GetString("namespace")
	policies, err := c.ListPolicies(ctx, namespace)
	if err != nil {
		return fmt.Errorf("listing policies: %w", err)
	}

	format := viper.GetString("output")

	switch format {
	case "json":
		data, _ := json.MarshalIndent(policies, "", "  ")
		fmt.Println(string(data))
	default:
		if len(policies) == 0 {
			fmt.Println("No policies loaded")
			return nil
		}

		fmt.Printf("%-30s %-15s %-8s\n",
			"NAME", "NAMESPACE", "RULES")
		fmt.Println(strings.Repeat("-", 60))

		for _, p := range policies {
			fmt.Printf("%-30s %-15s %-8d\n",
				p.Name,
				p.Namespace,
				p.RuleCount,
			)
		}
	}

	return nil
}

func runPolicyGet(cmd *cobra.Command, args []string) error {
	// Implementation would fetch and display policy details
	fmt.Printf("Getting policy: %s\n", args[0])
	return nil
}

func runPolicyPush(cmd *cobra.Command, args []string) error {
	// Policy push not yet implemented via HTTP API
	// Policies are loaded from the --policy-dir on server startup
	fmt.Println("Policy push is not yet implemented.")
	fmt.Println("To add policies, place them in the policy directory and restart the server,")
	fmt.Println("or use 'garmr policy reload' if the server supports hot reloading.")
	return nil
}

func runPolicyDelete(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}
	serverAddr = strings.Replace(serverAddr, ":9090", ":8080", 1)

	cfg := client.Config{
		Address: serverAddr,
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer c.Close()

	name := args[0]
	namespace, _ := cmd.Flags().GetString("namespace")
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		fmt.Printf("Delete policy '%s/%s'? [y/N]: ", namespace, name)
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	deleted, err := c.DeletePolicy(ctx, name, namespace)
	if err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}

	if deleted {
		fmt.Printf("✓ Policy '%s/%s' deleted\n", namespace, name)
	} else {
		fmt.Printf("Policy '%s/%s' not found\n", namespace, name)
	}

	return nil
}

func runPolicyReload(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}
	serverAddr = strings.Replace(serverAddr, ":9090", ":8080", 1)

	cfg := client.Config{
		Address: serverAddr,
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer c.Close()

	fmt.Println("Reloading policies...")

	result, err := c.ReloadPolicies(ctx)
	if err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}

	format := viper.GetString("output")
	if format == "json" {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		if result.Success {
			fmt.Printf("✓ Reloaded %d policies in %dms\n", result.PoliciesLoaded, result.ReloadTimeMs)
			fmt.Printf("  Policy directory: %s\n", result.PolicyDir)
		} else {
			fmt.Printf("✗ Reload failed: %s\n", result.Error)
		}
	}

	return nil
}
