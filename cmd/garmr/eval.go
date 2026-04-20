// cmd/garmr/eval.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/infrashift/garmr/internal/client"
	"github.com/infrashift/garmr/internal/input"
)

var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate input against policies",
	Long: `Evaluate JSON/YAML input against loaded policies.

The eval command sends input to the Garmr server for policy evaluation
and returns the decision with any violations.

NAMESPACE FILTERING:
  Policies are organized into namespaces for logical grouping.
  Use -n/--namespace to filter by namespace.

  Common namespaces:
    security/     Security controls and vulnerability checks
    compliance/   Regulatory requirements (GDPR, PCI-DSS, HIPAA)
    governance/   Organizational standards and labeling
    release/      Release management and promotion gates
    sre/          Reliability and observability requirements

EVALUATION MODES:
  By default, all matching rules are evaluated and results aggregated.
  Some policies use fail-fast mode to stop on first critical failure.
  
  The response indicates:
    - Whether fail-fast was triggered
    - Which rule caused termination
    - How many rules were skipped

Examples:
  # Evaluate a file against all policies
  garmr eval --input deployment.json

  # Evaluate against specific namespace
  garmr eval --input pod.json -n security

  # Evaluate against multiple namespaces
  garmr eval --input pod.json -n security -n compliance

  # Evaluate against all namespaces
  garmr eval --input pod.json --all-namespaces

  # Evaluate specific policies
  garmr eval --input pod.json --policy security/container-security

  # Filter by category or tags
  garmr eval --input pod.json --category security --tag cis-benchmark

  # Evaluate from stdin
  cat resource.json | garmr eval --input -

  # Strict mode (fail on warnings)
  garmr eval --input resource.json --strict --fail-on-warn

  # Output as JSON for CI/CD integration
  garmr eval --input resource.json -o json`,
	RunE: runEval,
}

func init() {
	// Input options
	evalCmd.Flags().StringP("input", "i", "", "input file (- for stdin)")
	evalCmd.Flags().StringP("data", "d", "", "inline JSON/YAML data")
	evalCmd.Flags().StringP("format", "f", "auto", "input format: json, yaml, auto (default: auto-detect)")

	// Policy selection
	evalCmd.Flags().StringSliceP("policy", "p", nil, "specific policies to evaluate (namespace/name)")
	evalCmd.Flags().StringSliceP("namespace", "n", nil, "policy namespace(s) to evaluate")
	evalCmd.Flags().BoolP("all-namespaces", "A", false, "evaluate against all namespaces")

	// Filtering
	evalCmd.Flags().StringSlice("category", nil, "filter by rule category")
	evalCmd.Flags().StringSlice("exclude-category", nil, "exclude rules by category")
	evalCmd.Flags().StringSlice("tag", nil, "filter by rule tag")
	evalCmd.Flags().StringSlice("exclude-tag", nil, "exclude rules by tag")

	// Evaluation options
	evalCmd.Flags().Bool("strict", false, "fail on warnings")
	evalCmd.Flags().Bool("trace", false, "enable evaluation trace")
	evalCmd.Flags().Bool("include-passed", false, "include passed rules in output")
	evalCmd.Flags().Bool("dry-run", false, "evaluate without enforcement")
	evalCmd.Flags().Bool("fail-on-warn", false, "exit with error on warnings")
	evalCmd.Flags().Bool("fail-fast", false, "stop on first failure (override policy setting)")

	// Request tracking
	evalCmd.Flags().String("request-id", "", "request ID for audit correlation (e.g., CI job ID)")

	evalCmd.MarkFlagRequired("input")
}

func runEval(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := client.Config{
		Address: viper.GetString("server"),
		Timeout: 30 * time.Second,
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}
	defer c.Close()

	// Read input
	input, err := readInput(cmd)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	// Build options
	namespaces, _ := cmd.Flags().GetStringSlice("namespace")
	namespace := ""
	if len(namespaces) > 0 {
		namespace = namespaces[0]
	}
	policies, _ := cmd.Flags().GetStringSlice("policy")
	requestID, _ := cmd.Flags().GetString("request-id")

	opts := client.EvaluateOptions{
		Namespace:     namespace,
		Policies:      policies,
		Trace:         mustBool(cmd.Flags().GetBool("trace")),
		IncludePassed: mustBool(cmd.Flags().GetBool("include-passed")),
		Strict:        mustBool(cmd.Flags().GetBool("strict")),
		RequestID:     requestID,
	}

	// Evaluate
	result, err := c.Evaluate(ctx, input, opts)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	// Output result
	if err := outputResult(cmd, result); err != nil {
		return err
	}

	// Determine exit code
	failOnWarn, _ := cmd.Flags().GetBool("fail-on-warn")

	switch result.Decision {
	case "deny":
		osExit(1)
	case "warn":
		if failOnWarn {
			osExit(2)
		}
	}

	return nil
}

func readInput(cmd *cobra.Command) (map[string]interface{}, error) {
	parser := input.NewParser()

	// Get format preference
	formatStr, _ := cmd.Flags().GetString("format")
	format, err := input.ParseFormat(formatStr)
	if err != nil {
		return nil, fmt.Errorf("invalid format: %w", err)
	}

	// Check for inline data first
	if data, _ := cmd.Flags().GetString("data"); data != "" {
		result, err := parser.Parse([]byte(data), format)
		if err != nil {
			return nil, fmt.Errorf("parsing inline data: %w", err)
		}
		return result, nil
	}

	// Read from file or stdin
	inputPath, _ := cmd.Flags().GetString("input")

	var data []byte

	if inputPath == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		// For stdin, use format flag or auto-detect
		result, err := parser.Parse(data, format)
		if err != nil {
			return nil, fmt.Errorf("parsing stdin: %w", err)
		}
		return result, nil
	}

	// For files, auto-detect from extension if format is auto
	if format == input.FormatAuto {
		result, _, err := parser.ParseFile(inputPath)
		if err != nil {
			return nil, fmt.Errorf("parsing file: %w", err)
		}
		return result, nil
	}

	// Use specified format
	data, err = os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	result, err := parser.Parse(data, format)
	if err != nil {
		return nil, fmt.Errorf("parsing input: %w", err)
	}

	return result, nil
}

func outputResult(cmd *cobra.Command, result *client.EvaluateResult) error {
	format := viper.GetString("output")
	quiet, _ := cmd.Flags().GetBool("quiet")

	switch format {
	case "json":
		return outputJSON(result)
	case "yaml":
		return outputYAML(result)
	default:
		return outputTable(result, quiet)
	}
}

func outputJSON(result *client.EvaluateResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputYAML(result *client.EvaluateResult) error {
	// Simple YAML output
	fmt.Printf("decision: %s\n", result.Decision)
	if len(result.Results) > 0 {
		fmt.Println("results:")
		for _, r := range result.Results {
			fmt.Printf("  - rule_id: %s\n", r.RuleID)
			fmt.Printf("    passed: %v\n", r.Passed)
			if r.Message != "" {
				fmt.Printf("    message: %s\n", r.Message)
			}
		}
	}
	return nil
}

func outputTable(result *client.EvaluateResult, quiet bool) error {
	// Decision with color indicator
	var decisionSymbol string
	switch result.Decision {
	case "allow":
		decisionSymbol = "✓"
	case "deny":
		decisionSymbol = "✗"
	case "warn":
		decisionSymbol = "⚠"
	}

	if !quiet {
		fmt.Printf("\nDecision: %s %s\n\n", decisionSymbol, strings.ToUpper(result.Decision))
	}

	// Results table
	if len(result.Results) > 0 {
		if !quiet {
			fmt.Printf("%-12s %-30s %-10s %-8s %s\n",
				"SEVERITY", "POLICY/RULE", "RESULT", "ID", "MESSAGE")
			fmt.Println(strings.Repeat("-", 100))
		}

		for _, r := range result.Results {
			status := "PASS"
			if !r.Passed {
				status = "FAIL"
			}

			policyRule := fmt.Sprintf("%s/%s", r.PolicyNamespace, r.PolicyName)
			if len(policyRule) > 30 {
				policyRule = policyRule[:27] + "..."
			}

			msg := r.Message
			if len(msg) > 40 {
				msg = msg[:37] + "..."
			}

			fmt.Printf("%-12s %-30s %-10s %-8s %s\n",
				strings.ToUpper(r.Severity),
				policyRule,
				status,
				r.RuleID,
				msg,
			)
		}
	}

	// Metrics
	if !quiet && result.Metrics.PoliciesEvaluated > 0 {
		fmt.Printf("\nEvaluated %d policies, %d rules in %s\n",
			result.Metrics.PoliciesEvaluated,
			result.Metrics.RulesEvaluated,
			time.Duration(result.Metrics.EvaluationTimeNs),
		)
	}

	return nil
}

func mustBool(b bool, _ error) bool { return b }
