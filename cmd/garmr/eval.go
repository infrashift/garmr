// cmd/garmr/eval.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/api"
	"github.com/infrashift/garmr/internal/client"
	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/input"
)

var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate input against policies",
	Long: `Evaluate JSON/YAML input against loaded policies.

The eval command sends input to the Garmr server for policy evaluation
and returns the decision with any violations.

LOCAL EVALUATION:
  --policy-dir evaluates in-process instead, with no server: the policies
  are loaded through the server's own loader (a directory, walked
  recursively, or a single .cue file) and evaluated by the same engine.
  The output, decision and exit codes are identical to a server
  evaluation. Use it in CI and in offline environments. No audit record
  is written; the request ID still appears in the output.

  Locally, the input is also checked against each policy's
  spec.inputSchema, when one is declared. Input that does not conform is
  an error (exit 2) that lists what is wrong, rather than a decision.

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
  garmr eval --input resource.json -o json

  # Evaluate locally, without a server
  garmr eval --local --policy-dir policies/ --input review.json -n review`,
	RunE: runEval,
}

func init() {
	// Input options
	evalCmd.Flags().StringP("input", "i", "", "input file (- for stdin)")
	evalCmd.Flags().StringP("data", "d", "", "inline JSON/YAML data")
	evalCmd.Flags().StringP("format", "f", "auto", "input format: json, yaml, auto (default: auto-detect)")

	// Policy selection
	evalCmd.Flags().StringSliceP("policy", "p", nil, "specific policies to evaluate: namespace/name, or a bare name resolved in --namespace (default \"default\")")
	evalCmd.Flags().StringP("namespace", "n", "", "policy namespace to evaluate")

	// Request tracking
	evalCmd.Flags().String("request-id", "", "request ID for audit correlation (e.g., CI job ID)")

	// Local evaluation
	evalCmd.Flags().Bool("local", false, "evaluate in-process, without a server (requires --policy-dir)")
	evalCmd.Flags().String("policy-dir", "", "policy directory or .cue file to evaluate against locally (implies --local)")
	evalCmd.Flags().Duration("timeout", api.DefaultEvaluationTimeout, "evaluation timeout for --local")
}

func runEval(cmd *cobra.Command, args []string) error {
	local, _ := cmd.Flags().GetBool("local")
	policyDir, _ := cmd.Flags().GetString("policy-dir")
	if local && policyDir == "" {
		return errors.New("--local requires --policy-dir")
	}

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
	var result *client.EvaluateResult
	if policyDir != "" {
		timeout, _ := cmd.Flags().GetDuration("timeout")
		result, err = evaluateLocal(policyDir, input, opts, timeout)
	} else {
		result, err = evaluateRemote(input, opts)
	}
	if err != nil {
		return err
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
		osExit(exitNegative)
	}

	return nil
}

// evaluateRemote sends the evaluation to the configured server.
func evaluateRemote(input map[string]interface{}, opts client.EvaluateOptions) (*client.EvaluateResult, error) {
	c, ctx, cleanup, err := newServerClient()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	result, err := c.Evaluate(ctx, input, opts)
	if err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}
	return result, nil
}

// evaluateLocal evaluates in-process against the policies at policyDir.
//
// Every step mirrors the server path so the result is the one a server
// loaded from the same directory would return: the server's loader, a JSON
// round trip of the input (numbers reach the engine as float64, as they do
// over the wire), the server's response converter, and the same decode into
// the client's result type.
func evaluateLocal(policyDir string, input map[string]interface{}, opts client.EvaluateOptions, timeout time.Duration) (*client.EvaluateResult, error) {
	eng, err := loadLocalEngine(policyDir)
	if err != nil {
		return nil, err
	}

	wireInput, err := jsonRoundTrip(input)
	if err != nil {
		return nil, fmt.Errorf("encoding input: %w", err)
	}

	requestID := opts.RequestID
	if requestID == "" {
		requestID = uuid.New().String()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := eng.Evaluate(ctx, &engine.EvaluateRequest{
		Input:     wireInput,
		Namespace: opts.Namespace,
		Policies:  opts.Policies,
		// Validate the input against each policy's spec.inputSchema: the
		// CLI can afford the CUE compile the server's hot path avoids.
		Options: engine.EvaluateOptions{IncludePassed: opts.IncludePassed, CheckInputSchema: true},
	})
	if err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}

	body, err := json.Marshal(api.NewEvaluateBody(resp, requestID))
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}
	var result client.EvaluateResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding result: %w", err)
	}
	return &result, nil
}

// loadLocalEngine builds an engine loaded from a policy directory or a
// single .cue file, through the same loader the server and `garmr validate`
// use. A load failure is fatal: evaluating a partial set would be the
// fail-open the server's loader exists to prevent.
func loadLocalEngine(policyDir string) (*engine.Engine, error) {
	info, err := os.Stat(policyDir)
	if err != nil {
		return nil, fmt.Errorf("policy dir: %w", err)
	}
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		return nil, fmt.Errorf("creating engine: %w", err)
	}
	if info.IsDir() {
		err = eng.LoadPoliciesFromDir(context.Background(), policyDir)
	} else {
		_, err = eng.LoadPoliciesFromFile(context.Background(), policyDir)
	}
	if err != nil {
		return nil, fmt.Errorf("loading policies from %s: %w", policyDir, err)
	}
	return eng, nil
}

// jsonRoundTrip re-decodes v the way the server decodes a request body, so
// YAML integers and other Go-typed values reach the engine as JSON values.
func jsonRoundTrip(v map[string]interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
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
		result, parseErr := parser.Parse([]byte(data), format)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing inline data: %w", parseErr)
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
		result, parseErr := parser.Parse(data, format)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing stdin: %w", parseErr)
		}
		return result, nil
	}

	// For files, auto-detect from extension if format is auto
	if format == input.FormatAuto {
		result, _, parseErr := parser.ParseFile(inputPath)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing file: %w", parseErr)
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
			if len(r.Findings) > 0 {
				fmt.Println("    findings:")
				for _, f := range r.Findings {
					fmt.Printf("      - path: %s\n", f.Path)
					fmt.Printf("        index: %d\n", f.Index)
					if len(f.Details) > 0 {
						fmt.Println("        details:")
						for _, k := range sortedKeys(f.Details) {
							fmt.Printf("          %s: %v\n", k, f.Details[k])
						}
					}
				}
				if r.FindingsTruncated {
					fmt.Println("    findings_truncated: true")
				}
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
			for _, f := range r.Findings {
				fmt.Printf("%-12s %-30s %-10s %-8s  • %s\n", "", "", "", "", formatFinding(f))
			}
			if r.FindingsTruncated {
				fmt.Printf("%-12s %-30s %-10s %-8s  • … more failing elements not listed\n", "", "", "", "")
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

// formatFinding renders a finding as its path followed by its details in
// name order: "risk_files[3] file=a.go line=12".
func formatFinding(f client.Finding) string {
	var b strings.Builder
	b.WriteString(f.Path)
	for _, k := range sortedKeys(f.Details) {
		fmt.Fprintf(&b, " %s=%v", k, f.Details[k])
	}
	return b.String()
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
