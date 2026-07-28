// cmd/garmr/eval.go
package main

import (
	"context"
	"encoding/json"
	"errors"
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

  # Evaluate specific policies
  garmr eval --input pod.json --policy security/container-security

  # Evaluate from stdin
  cat resource.json | garmr eval --input -

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
	evalCmd.Flags().StringP("namespace", "n", "", "policy namespace to evaluate")

	// Request tracking
	evalCmd.Flags().String("request-id", "", "request ID for audit correlation (e.g., CI job ID)")
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
	namespace, _ := cmd.Flags().GetString("namespace")
	policies, _ := cmd.Flags().GetStringSlice("policy")
	requestID, _ := cmd.Flags().GetString("request-id")

	verboseFlag := cmd.Flags().Lookup("verbose")
	verboseSet := verboseFlag != nil && verboseFlag.Changed
	verboseValue, _ := cmd.Flags().GetBool("verbose")
	includePassed := verboseSet && verboseValue
	suppressDetails := verboseSet && !verboseValue

	opts := client.EvaluateOptions{
		Namespace:     namespace,
		Policies:      policies,
		IncludePassed: includePassed,
		RequestID:     requestID,
	}

	// Evaluate
	result, err := c.Evaluate(ctx, input, opts)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	// Output result
	if err := outputResult(cmd, result, suppressDetails); err != nil {
		return err
	}

	// Exit code is determined by the policy decision — no client-side
	// overrides. Warn is advisory by design; if a team wants warnings to
	// gate CI, the policy author should change enforcement.action to
	// "deny" so the override lives in code review, not in a CLI flag.
	if result.Decision == "deny" {
		osExit(1)
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
	if inputPath == "" {
		return nil, errors.New("one of --input or --data is required")
	}

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

func outputResult(cmd *cobra.Command, result *client.EvaluateResult, suppressDetails bool) error {
	format := viper.GetString("output")
	quiet, _ := cmd.Flags().GetBool("quiet")

	switch format {
	case "json":
		return outputJSON(result)
	case "yaml":
		return outputYAML(result)
	default:
		return outputTable(result, quiet, suppressDetails)
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
			if r.Remediation != "" {
				fmt.Printf("    remediation: %s\n", r.Remediation)
			}
		}
	}
	return nil
}

func outputTable(result *client.EvaluateResult, quiet, suppressDetails bool) error {
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
	if !suppressDetails && len(result.Results) > 0 {
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

			if !r.Passed && r.Remediation != "" {
				fmt.Printf("%-12s %-30s %-10s %-8s  ↳ %s\n", "", "", "", "", r.Remediation)
			}
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

	// Rules that never ran. Reported because a partial evaluation is not the
	// same as a clean one, and the command's help text promises this.
	if !quiet {
		mode := result.EvaluationMode
		if mode.RulesSkipped > 0 {
			fmt.Printf("Evaluated %d of %d rules (%d skipped)\n",
				mode.RulesEvaluated, mode.TotalRulesInScope, mode.RulesSkipped)
		}
		if mode.DryRun {
			fmt.Println("Dry run: violations reported but not enforced")
		}
		if result.TerminatedEarly {
			if tr := result.TerminationRule; tr != nil {
				fmt.Printf("Terminated early at %s/%s#%s (fail-fast)\n",
					tr.PolicyNamespace, tr.PolicyName, tr.RuleID)
			} else {
				fmt.Println("Terminated early (fail-fast)")
			}
		}
	}

	return nil
}
