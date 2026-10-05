// cmd/garmr/test_cmd.go
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

	qtesting "github.com/infrashift/garmr/internal/testing"
)

var testCmd = &cobra.Command{
	Use:   "test <policy-file> [test-file]",
	Short: "Run policy tests",
	Long: `Run tests against Garmr policies to verify expected behavior.

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
  garmr test policies/release-gate.cue policies/release-gate_test.cue

  # Run all tests in a directory
  garmr test policies/ --recursive

  # Run with verbose output
  garmr test policies/release-gate.cue -v

  # Run specific test by name
  garmr test policies/ --filter "valid release"

  # Output JSON results
  garmr test policies/ --format json
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
	// No -v shorthand: the root command already owns -v/--verbose, and a
	// local one shadowed it. runTest reads the inherited flag instead.
	testCmd.Flags().BoolVarP(&testRecursive, "recursive", "r", false,
		"Process directories recursively")
	testCmd.Flags().StringVar(&testFilter, "filter", "",
		"Filter tests by name (substring match)")
	// --format, not -o: the root -o/--output takes table|json|yaml, a
	// different value space from this command's text|json|tap, so sharing
	// the shorthand made `garmr test -o table` silently invalid.
	testCmd.Flags().StringVar(&testOutput, "format", "text",
		"Output format: text, json, tap")
	testCmd.Flags().BoolVar(&testFailFast, "fail-fast", false,
		"Stop on first test failure")
}

func runTest(cmd *cobra.Command, args []string) error {
	// Inherited from the root command's persistent flags.
	testVerbose, _ = cmd.Flags().GetBool("verbose")
	runner, err := qtesting.NewRunner(testVerbose)
	if err != nil {
		return fmt.Errorf("creating test runner: %w", err)
	}

	policyFiles, testFiles, err := collectTestFiles(args, testRecursive)
	if err != nil {
		return err
	}
	if len(testFiles) == 0 {
		return fmt.Errorf("no test files found (use *_test.cue naming convention)")
	}

	for _, pf := range policyFiles {
		if loadErr := runner.LoadPolicyFile(pf); loadErr != nil {
			return fmt.Errorf("loading policy %s: %w", pf, loadErr)
		}
		if testVerbose {
			fmt.Printf("Loaded policy: %s\n", pf)
		}
	}

	allResults, totals, err := runTestSuites(context.Background(), runner, testFiles)
	if err != nil {
		return err
	}

	if testOutput == "json" {
		printJSON(allResults)
	}
	if len(allResults) > 1 && testOutput == "text" {
		fmt.Printf("\n=== Summary ===\n")
		fmt.Printf("Suites: %d\n", len(allResults))
		fmt.Printf("Tests:  %d passed, %d failed, %d skipped\n",
			totals.passed, totals.failed, totals.skipped)
	}

	if totals.failed > 0 {
		return resultError{fmt.Errorf("%d test(s) failed", totals.failed)}
	}
	return nil
}

// collectTestFiles splits the arguments into policy files and *_test.cue
// suites. Directory arguments are walked (only the top level unless recursive
// is set), and when no suite was named explicitly, each policy file's sibling
// _test.cue is picked up.
func collectTestFiles(args []string, recursive bool) (policyFiles, testFiles []string, err error) {
	classify := func(path string) {
		if strings.HasSuffix(path, "_test.cue") {
			testFiles = append(testFiles, path)
		} else {
			policyFiles = append(policyFiles, path)
		}
	}

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, nil, fmt.Errorf("accessing %s: %w", arg, err)
		}

		if !info.IsDir() {
			classify(arg)
			continue
		}

		walkErr := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Non-recursive mode only descends into the argument itself.
			// (The root must not be skipped: SkipDir on it used to abort the
			// whole walk, so `garmr test <dir>` without -r found nothing.)
			if !recursive && path != arg && filepath.Dir(path) != arg {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, ".cue") {
				classify(path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, nil, fmt.Errorf("walking directory: %w", walkErr)
		}
	}

	// If no explicit test files, look for corresponding _test.cue files
	if len(testFiles) == 0 {
		for _, pf := range policyFiles {
			testFile := strings.TrimSuffix(pf, ".cue") + "_test.cue"
			if _, statErr := os.Stat(testFile); statErr == nil {
				testFiles = append(testFiles, testFile)
			}
		}
	}

	return policyFiles, testFiles, nil
}

// suiteTotals aggregates results across every suite of a run.
type suiteTotals struct {
	passed, failed, skipped int
}

// runTestSuites loads, filters, and runs each suite, streaming text/tap
// output as it goes and honouring --fail-fast.
func runTestSuites(ctx context.Context, runner *qtesting.Runner, testFiles []string) ([]*qtesting.SuiteResult, suiteTotals, error) {
	var allResults []*qtesting.SuiteResult
	var totals suiteTotals

	for _, tf := range testFiles {
		suite, err := runner.LoadTestSuiteFile(tf)
		if err != nil {
			return nil, totals, fmt.Errorf("loading test suite %s: %w", tf, err)
		}

		if testFilter != "" {
			suite.Tests = filterTestCases(suite.Tests, testFilter)
		}
		if len(suite.Tests) == 0 {
			continue
		}

		result := runner.RunSuite(ctx, suite)
		allResults = append(allResults, result)
		totals.passed += result.Passed
		totals.failed += result.Failed
		totals.skipped += result.Skipped

		switch testOutput {
		case "text":
			fmt.Print(qtesting.FormatResults(result, testVerbose))
		case "json":
			// Printed all together by the caller.
		case "tap":
			fmt.Print(formatTAP(result))
		}

		if testFailFast && result.Failed > 0 {
			break
		}
	}

	return allResults, totals, nil
}

// filterTestCases keeps the cases whose name contains the filter,
// case-insensitively.
func filterTestCases(cases []qtesting.TestCase, filter string) []qtesting.TestCase {
	var filtered []qtesting.TestCase
	for _, tc := range cases {
		if strings.Contains(strings.ToLower(tc.Name), strings.ToLower(filter)) {
			filtered = append(filtered, tc)
		}
	}
	return filtered
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
	_ = enc.Encode(results)
}
