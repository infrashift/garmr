// cmd/garmr/docs_cmd.go
// Documentation generation CLI commands
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"github.com/spf13/cobra"
)

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Documentation generation commands",
	Long:  `Generate human-readable documentation from CUE policies.`,
}

var docsGenerateCmd = &cobra.Command{
	Use:   "generate <policy-file-or-dir>",
	Short: "Generate markdown documentation",
	Long: `Generate markdown documentation from CUE policy files.

Supported output formats:
  - generic-markdown: Standard markdown (default)

Examples:
  # Generate docs for all policies in a directory
  garmr docs generate ./example-policies --output ./out/docs

  # Generate docs with specific format
  garmr docs generate ./example-policies --format generic-markdown --output ./out/docs

  # Generate recursively
  garmr docs generate ./policies --recursive --output ./docs
`,
	Args: cobra.ExactArgs(1),
	RunE: runDocsGenerate,
}

// Flags
var (
	docsFormat    string
	docsOutput    string
	docsRecursive bool
	docsAuthor    string
)

func init() {
	docsGenerateCmd.Flags().StringVarP(&docsFormat, "format", "f", "generic-markdown",
		"Output format (only generic-markdown is supported)")
	docsGenerateCmd.Flags().StringVarP(&docsOutput, "output", "o", "./docs/policies",
		"Output directory for generated docs")
	docsGenerateCmd.Flags().BoolVarP(&docsRecursive, "recursive", "r", true,
		"Process directories recursively")
	docsGenerateCmd.Flags().StringVar(&docsAuthor, "author", "",
		"Author name for front matter")

	docsCmd.AddCommand(docsGenerateCmd)
}

// PolicyDoc represents a parsed policy for documentation
type PolicyDoc struct {
	Name        string
	Namespace   string
	Description string
	Target      TargetDoc
	Rules       []RuleDoc
	Enforcement string
	Labels      map[string]string
	SourceFile  string
}

// TargetDoc represents target configuration
type TargetDoc struct {
	Resources []string
}

// RuleDoc represents a rule for documentation
type RuleDoc struct {
	ID          string
	Description string
	Severity    string
	Message     string
	Expression  string
}

func runDocsGenerate(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	if docsFormat != "generic-markdown" {
		return fmt.Errorf("invalid format: %s (supported: generic-markdown)", docsFormat)
	}

	// Find policy files
	policyFiles, err := findPolicyFiles(inputPath, docsRecursive)
	if err != nil {
		return err
	}

	if len(policyFiles) == 0 {
		return fmt.Errorf("no .cue files found in %s", inputPath)
	}

	fmt.Printf("Found %d policy file(s)\n", len(policyFiles))

	// Create output directory
	if err := os.MkdirAll(docsOutput, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Parse policies and generate docs
	ctx := cuecontext.New()
	var allPolicies []PolicyDoc

	for _, file := range policyFiles {
		policies, err := parsePoliciesFromFile(ctx, file)
		if err != nil {
			fmt.Printf("Warning: skipping %s: %v\n", file, err)
			continue
		}
		allPolicies = append(allPolicies, policies...)
	}

	if len(allPolicies) == 0 {
		return fmt.Errorf("no valid policies found")
	}

	fmt.Printf("Parsed %d policies\n", len(allPolicies))

	// Group by namespace
	byNamespace := make(map[string][]PolicyDoc)
	for _, p := range allPolicies {
		ns := p.Namespace
		if ns == "" {
			ns = "default"
		}
		byNamespace[ns] = append(byNamespace[ns], p)
	}

	// Generate documentation
	for ns, policies := range byNamespace {
		nsDir := filepath.Join(docsOutput, ns)
		if err := os.MkdirAll(nsDir, 0755); err != nil {
			return fmt.Errorf("creating namespace directory: %w", err)
		}

		// Generate individual policy docs
		for _, policy := range policies {
			filename := filepath.Join(nsDir, policy.Name+".md")
			if err := generatePolicyDoc(policy, filename, docsFormat); err != nil {
				return fmt.Errorf("generating %s: %w", filename, err)
			}
			fmt.Printf("Generated: %s\n", filename)
		}

		// Generate namespace index
		indexFile := filepath.Join(nsDir, "README.md")
		if err := generateNamespaceIndex(ns, policies, indexFile, docsFormat); err != nil {
			return fmt.Errorf("generating index: %w", err)
		}
		fmt.Printf("Generated: %s\n", indexFile)
	}

	// Generate root index
	rootIndex := filepath.Join(docsOutput, "README.md")
	if err := generateRootIndex(byNamespace, rootIndex, docsFormat); err != nil {
		return fmt.Errorf("generating root index: %w", err)
	}
	fmt.Printf("Generated: %s\n", rootIndex)

	fmt.Printf("\nDocumentation generated in %s\n", docsOutput)
	return nil
}

func findPolicyFiles(inputPath string, recursive bool) ([]string, error) {
	var policyFiles []string

	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, fmt.Errorf("accessing %s: %w", inputPath, err)
	}

	if info.IsDir() {
		if recursive {
			err = filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				// Skip hidden directories and common non-policy directories
				if info.IsDir() {
					name := info.Name()
					if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "cue.mod" {
						return filepath.SkipDir
					}
					return nil
				}
				if filepath.Ext(path) == ".cue" && !strings.HasSuffix(path, "_test.cue") {
					policyFiles = append(policyFiles, path)
				}
				return nil
			})
		} else {
			entries, err := os.ReadDir(inputPath)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".cue" && !strings.HasSuffix(entry.Name(), "_test.cue") {
					policyFiles = append(policyFiles, filepath.Join(inputPath, entry.Name()))
				}
			}
		}
	} else {
		policyFiles = []string{inputPath}
	}

	return policyFiles, err
}

func parsePoliciesFromFile(ctx *cue.Context, filePath string) ([]PolicyDoc, error) {
	cfg := &load.Config{
		Dir: filepath.Dir(filePath),
	}

	instances := load.Instances([]string{filepath.Base(filePath)}, cfg)
	var policies []PolicyDoc

	for _, inst := range instances {
		if inst.Err != nil {
			return nil, inst.Err
		}

		val := ctx.BuildInstance(inst)
		if val.Err() != nil {
			return nil, val.Err()
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

			policy := PolicyDoc{
				SourceFile: filePath,
			}

			// Extract metadata
			if nameVal := fieldVal.LookupPath(cue.ParsePath("metadata.name")); nameVal.Exists() {
				policy.Name, _ = nameVal.String()
			}
			if nsVal := fieldVal.LookupPath(cue.ParsePath("metadata.namespace")); nsVal.Exists() {
				policy.Namespace, _ = nsVal.String()
			}

			// Extract labels
			if labelsVal := fieldVal.LookupPath(cue.ParsePath("metadata.labels")); labelsVal.Exists() {
				policy.Labels = make(map[string]string)
				labelsIter, _ := labelsVal.Fields()
				for labelsIter.Next() {
					key := labelsIter.Label()
					val, _ := labelsIter.Value().String()
					policy.Labels[key] = val
				}
			}

			// Extract spec
			if descVal := fieldVal.LookupPath(cue.ParsePath("spec.description")); descVal.Exists() {
				policy.Description, _ = descVal.String()
			}

			// Extract target resources
			if targetVal := fieldVal.LookupPath(cue.ParsePath("spec.target.resources")); targetVal.Exists() {
				iter, _ := targetVal.List()
				for iter.Next() {
					v := iter.Value()
					if s, err := v.String(); err == nil {
						policy.Target.Resources = append(policy.Target.Resources, s)
					} else {
						// Structured resource selector
						if kindVal := v.LookupPath(cue.ParsePath("kind")); kindVal.Exists() {
							k, _ := kindVal.String()
							policy.Target.Resources = append(policy.Target.Resources, k)
						}
					}
				}
			}

			// Extract enforcement
			if actionVal := fieldVal.LookupPath(cue.ParsePath("spec.enforcement.action")); actionVal.Exists() {
				policy.Enforcement, _ = actionVal.String()
			}

			// Extract rules
			if rulesVal := fieldVal.LookupPath(cue.ParsePath("spec.rules")); rulesVal.Exists() {
				rulesIter, _ := rulesVal.List()
				for rulesIter.Next() {
					ruleVal := rulesIter.Value()
					rule := RuleDoc{}

					if idVal := ruleVal.LookupPath(cue.ParsePath("id")); idVal.Exists() {
						rule.ID, _ = idVal.String()
					}
					if descVal := ruleVal.LookupPath(cue.ParsePath("description")); descVal.Exists() {
						rule.Description, _ = descVal.String()
					}
					if sevVal := ruleVal.LookupPath(cue.ParsePath("severity")); sevVal.Exists() {
						rule.Severity, _ = sevVal.String()
					}
					if msgVal := ruleVal.LookupPath(cue.ParsePath("message")); msgVal.Exists() {
						rule.Message, _ = msgVal.String()
					}

					// Extract expression as JSON for display
					if exprVal := ruleVal.LookupPath(cue.ParsePath("expr")); exprVal.Exists() {
						exprBytes, _ := json.MarshalIndent(exprVal, "", "  ")
						rule.Expression = string(exprBytes)
					}

					policy.Rules = append(policy.Rules, rule)
				}
			}

			policies = append(policies, policy)
		}
	}

	return policies, nil
}

func generatePolicyDoc(policy PolicyDoc, filename string, format string) error {
	tmpl := getPolicyTemplate(format)

	t, err := template.New("policy").Parse(tmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	data := map[string]interface{}{
		"Policy":    policy,
		"Generated": time.Now().UTC().Format(time.RFC3339),
		"Format":    format,
	}

	if err := t.Execute(&buf, data); err != nil {
		return err
	}

	return os.WriteFile(filename, buf.Bytes(), 0644)
}

func generateNamespaceIndex(namespace string, policies []PolicyDoc, filename string, format string) error {
	// Sort policies by name
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})

	tmpl := getNamespaceIndexTemplate(format)

	t, err := template.New("namespace").Parse(tmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	data := map[string]interface{}{
		"Namespace": namespace,
		"Policies":  policies,
		"Generated": time.Now().UTC().Format(time.RFC3339),
	}

	if err := t.Execute(&buf, data); err != nil {
		return err
	}

	return os.WriteFile(filename, buf.Bytes(), 0644)
}

func generateRootIndex(byNamespace map[string][]PolicyDoc, filename string, format string) error {
	// Get sorted namespace list
	var namespaces []string
	for ns := range byNamespace {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	// Count totals
	totalPolicies := 0
	totalRules := 0
	for _, policies := range byNamespace {
		totalPolicies += len(policies)
		for _, p := range policies {
			totalRules += len(p.Rules)
		}
	}

	tmpl := getRootIndexTemplate(format)

	t, err := template.New("root").Parse(tmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	data := map[string]interface{}{
		"Namespaces":    namespaces,
		"ByNamespace":   byNamespace,
		"TotalPolicies": totalPolicies,
		"TotalRules":    totalRules,
		"Generated":     time.Now().UTC().Format(time.RFC3339),
	}

	if err := t.Execute(&buf, data); err != nil {
		return err
	}

	return os.WriteFile(filename, buf.Bytes(), 0644)
}

func getPolicyTemplate(format string) string {
	return `# {{ .Policy.Name }}

{{ .Policy.Description }}

## Overview

| Property | Value |
|----------|-------|
| **Namespace** | ` + "`{{ .Policy.Namespace }}`" + ` |
| **Enforcement** | ` + "`{{ .Policy.Enforcement }}`" + ` |
| **Rules** | {{ len .Policy.Rules }} |
{{- if .Policy.Target.Resources }}
| **Targets** | {{ range $i, $r := .Policy.Target.Resources }}{{if $i}}, {{end}}` + "`{{ $r }}`" + `{{ end }} |
{{- end }}

{{- if .Policy.Labels }}

### Labels

| Key | Value |
|-----|-------|
{{- range $k, $v := .Policy.Labels }}
| ` + "`{{ $k }}`" + ` | ` + "`{{ $v }}`" + ` |
{{- end }}
{{- end }}

## Rules

{{- range .Policy.Rules }}

### {{ .ID }}: {{ .Description }}

| Property | Value |
|----------|-------|
| **Severity** | ` + "`{{ .Severity }}`" + ` |
| **Message** | {{ .Message }} |

{{- if .Expression }}

<details>
<summary>Expression</summary>

` + "```json" + `
{{ .Expression }}
` + "```" + `

</details>
{{- end }}

{{- end }}

---

*Generated: {{ .Generated }}*
`
}

func getNamespaceIndexTemplate(format string) string {
	return `# {{ .Namespace }} Policies

This namespace contains {{ len .Policies }} policies.

## Policies

| Policy | Description | Rules | Enforcement |
|--------|-------------|-------|-------------|
{{- range .Policies }}
| [{{ .Name }}](./{{ .Name }}.md) | {{ .Description }} | {{ len .Rules }} | ` + "`{{ .Enforcement }}`" + ` |
{{- end }}

---

*Generated: {{ .Generated }}*
`
}

func getRootIndexTemplate(format string) string {
	return `# Policy Documentation

This documentation covers all policies loaded in Garmr.

## Summary

| Metric | Count |
|--------|-------|
| **Namespaces** | {{ len .Namespaces }} |
| **Policies** | {{ .TotalPolicies }} |
| **Rules** | {{ .TotalRules }} |

## Namespaces

{{- range .Namespaces }}
{{ $policies := index $.ByNamespace . }}
### [{{ . }}](./{{ . }}/README.md)

{{ len $policies }} policies

| Policy | Rules | Enforcement |
|--------|-------|-------------|
{{- range $policies }}
| [{{ .Name }}](./{{ . }}/{{ .Name }}.md) | {{ len .Rules }} | ` + "`{{ .Enforcement }}`" + ` |
{{- end }}

{{- end }}

---

*Generated: {{ .Generated }}*
`
}
