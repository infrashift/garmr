// cmd/q/test_cmd.go
// Policy testing CLI commands
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	qtesting "github.com/infrashift/q-policy-agent/internal/testing"
)

var testCmd = &cobra.Command{
	Use:   "test <policy-file> [test-file]",
	Short: "Run policy tests",
	Long: `Run tests against Q policies to verify expected behavior.

Test files use CUE format to define test cases with inputs and expected outputs.

Test File Format:
  {
      policy: "my-policy"
      
      tests: [{
          name: "test case name"
          input: {
              // input data for the policy
          }
          expect: {
              decision: "allow" | "deny"
              violations: [{id: "RULE-001"}]
              noViolations: true
          }
      }]
  }

Examples:
  # Run tests for a policy
  q test policies/release-gate.cue policies/release-gate_test.cue

  # Run all tests in a directory
  q test policies/ --recursive

  # Run with verbose output
  q test policies/release-gate.cue -v

  # Run specific test by name
  q test policies/ --filter "valid release"

  # Output JSON results
  q test policies/ --output json
`,
	Args: cobra.MinimumNArgs(1),
	RunE: runTest,
}

// Flags
var (
	testVerbose   bool
	testRecursive bool
	testFilter    string
	testOutput    string
	testFailFast  bool
)

func init() {
	testCmd.Flags().BoolVarP(&testVerbose, "verbose", "v", false,
		"Show detailed test output")
	testCmd.Flags().BoolVarP(&testRecursive, "recursive", "r", false,
		"Process directories recursively")
	testCmd.Flags().StringVar(&testFilter, "filter", "",
		"Filter tests by name (substring match)")
	testCmd.Flags().StringVarP(&testOutput, "output", "o", "text",
		"Output format: text, json, tap")
	testCmd.Flags().BoolVar(&testFailFast, "fail-fast", false,
		"Stop on first test failure")
}

func runTest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	runner := qtesting.NewRunner(testVerbose)

	// Collect policy and test files
	var policyFiles, testFiles []string

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return fmt.Errorf("accessing %s: %w", arg, err)
		}

		if info.IsDir() {
			// Find all .cue files
			err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !testRecursive && filepath.Dir(path) != arg {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if !info.IsDir() && strings.HasSuffix(path, ".cue") {
					if strings.HasSuffix(path, "_test.cue") {
						testFiles = append(testFiles, path)
					} else {
						policyFiles = append(policyFiles, path)
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("walking directory: %w", err)
			}
		} else {
			if strings.HasSuffix(arg, "_test.cue") {
				testFiles = append(testFiles, arg)
			} else {
				policyFiles = append(policyFiles, arg)
			}
		}
	}

	// If no explicit test files, look for corresponding _test.cue files
	if len(testFiles) == 0 {
		for _, pf := range policyFiles {
			testFile := strings.TrimSuffix(pf, ".cue") + "_test.cue"
			if _, err := os.Stat(testFile); err == nil {
				testFiles = append(testFiles, testFile)
			}
		}
	}

	if len(testFiles) == 0 {
		return fmt.Errorf("no test files found (use *_test.cue naming convention)")
	}

	// Load policies
	for _, pf := range policyFiles {
		if err := runner.LoadPolicyFile(pf); err != nil {
			return fmt.Errorf("loading policy %s: %w", pf, err)
		}
		if testVerbose {
			fmt.Printf("Loaded policy: %s\n", pf)
		}
	}

	// Run tests
	var allResults []*qtesting.SuiteResult
	totalPassed, totalFailed, totalSkipped := 0, 0, 0

	for _, tf := range testFiles {
		suite, err := runner.LoadTestSuiteFile(tf)
		if err != nil {
			return fmt.Errorf("loading test suite %s: %w", tf, err)
		}

		// Apply filter if specified
		if testFilter != "" {
			var filtered []qtesting.TestCase
			for _, tc := range suite.Tests {
				if strings.Contains(strings.ToLower(tc.Name), strings.ToLower(testFilter)) {
					filtered = append(filtered, tc)
				}
			}
			suite.Tests = filtered
		}

		if len(suite.Tests) == 0 {
			continue
		}

		result := runner.RunSuite(ctx, suite)
		allResults = append(allResults, result)

		totalPassed += result.Passed
		totalFailed += result.Failed
		totalSkipped += result.Skipped

		// Output based on format
		switch testOutput {
		case "text":
			fmt.Print(qtesting.FormatResults(result, testVerbose))
		case "json":
			// Will output all at end
		case "tap":
			fmt.Print(formatTAP(result))
		}

		// Fail fast check
		if testFailFast && result.Failed > 0 {
			break
		}
	}

	// JSON output (all results together)
	if testOutput == "json" {
		printJSON(allResults)
	}

	// Final summary for multiple suites
	if len(allResults) > 1 && testOutput == "text" {
		fmt.Printf("\n=== Summary ===\n")
		fmt.Printf("Suites: %d\n", len(allResults))
		fmt.Printf("Tests:  %d passed, %d failed, %d skipped\n",
			totalPassed, totalFailed, totalSkipped)
	}

	// Exit with error if any tests failed
	if totalFailed > 0 {
		return fmt.Errorf("%d test(s) failed", totalFailed)
	}

	return nil
}

func formatTAP(result *qtesting.SuiteResult) string {
	var sb strings.Builder

	sb.WriteString("TAP version 13\n")
	sb.WriteString(fmt.Sprintf("1..%d\n", result.Total))

	for i, tr := range result.Results {
		num := i + 1
		if tr.Skipped {
			sb.WriteString(fmt.Sprintf("ok %d - %s # SKIP %s\n",
				num, tr.Name, tr.SkipReason))
		} else if tr.Passed {
			sb.WriteString(fmt.Sprintf("ok %d - %s\n", num, tr.Name))
		} else {
			sb.WriteString(fmt.Sprintf("not ok %d - %s\n", num, tr.Name))
			for _, f := range tr.Failures {
				sb.WriteString(fmt.Sprintf("  ---\n  message: %s\n  ---\n", f))
			}
		}
	}

	return sb.String()
}

func printJSON(results interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}
