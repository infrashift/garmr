// cmd/q/eval.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/infrashift/q-policy-agent/internal/client"
)

var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate input against policies",
	Long: `Evaluate JSON/YAML input against loaded policies.

The eval command sends input to the Q server for policy evaluation
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
  q eval --input deployment.json

  # Evaluate against specific namespace
  q eval --input pod.json -n security

  # Evaluate against multiple namespaces
  q eval --input pod.json -n security -n compliance

  # Evaluate against all namespaces
  q eval --input pod.json --all-namespaces

  # Evaluate specific policies
  q eval --input pod.json --policy security/container-security

  # Filter by category or tags
  q eval --input pod.json --category security --tag cis-benchmark

  # Evaluate from stdin
  cat resource.json | q eval --input -

  # Strict mode (fail on warnings)
  q eval --input resource.json --strict --fail-on-warn

  # Output as JSON for CI/CD integration
  q eval --input resource.json -o json`,
	RunE: runEval,
}

func init() {
	// Input options
	evalCmd.Flags().StringP("input", "i", "", "input file (- for stdin)")
	evalCmd.Flags().StringP("data", "d", "", "inline JSON data")

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

	// Create HTTP client
	serverAddr := viper.GetString("server")
	// Convert gRPC address format to HTTP if needed
	if serverAddr == "localhost:9090" {
		serverAddr = "http://localhost:8080"
	}
	// Add http:// prefix if missing
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}

	cfg := client.Config{
		Address: serverAddr,
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
		os.Exit(1)
	case "warn":
		if failOnWarn {
			os.Exit(2)
		}
	}

	return nil
}

func readInput(cmd *cobra.Command) (map[string]interface{}, error) {
	// Check for inline data first
	if data, _ := cmd.Flags().GetString("data"); data != "" {
		var input map[string]interface{}
		if err := json.Unmarshal([]byte(data), &input); err != nil {
			return nil, fmt.Errorf("parsing inline data: %w", err)
		}
		return input, nil
	}

	// Read from file or stdin
	inputPath, _ := cmd.Flags().GetString("input")

	var data []byte
	var err error

	if inputPath == "-" {
		data, err = os.ReadFile("/dev/stdin")
	} else {
		data, err = os.ReadFile(inputPath)
	}

	if err != nil {
		return nil, err
	}

	var input map[string]interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parsing input: %w", err)
	}

	return input, nil
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

func mustString(s string, _ error) string { return s }
func mustBool(b bool, _ error) bool       { return b }
