// plugins/markdown/main.go
// Package main provides the markdown documentation generator plugin for Q Policy Agent.
// This plugin generates human-readable documentation from CUE policies.
//
// Supported output formats:
//   - github: GitHub-flavored markdown
//   - hugo: Hugo static site generator (with YAML front matter)
//   - astro: Astro framework (with YAML front matter + components)
//   - docusaurus: Docusaurus documentation (with front matter)
//   - plain: Plain markdown without front matter
//
// Build with:
//
//	go build -buildmode=plugin -o markdown.so ./plugins/markdown
package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"gopkg.in/yaml.v3"

	"github.com/infrashift/q-policy-agent/internal/plugin"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// MarkdownPlugin generates documentation from CUE policies.
type MarkdownPlugin struct {
	config    MarkdownConfig
	templates map[string]*template.Template
	ctx       *cue.Context
}

// MarkdownConfig configures the documentation generator.
type MarkdownConfig struct {
	// OutputFormat: github, hugo, astro, docusaurus, plain
	OutputFormat string `json:"outputFormat"`

	// OutputDir for generated files
	OutputDir string `json:"outputDir"`

	// TemplateDir for custom templates (optional)
	TemplateDir string `json:"templateDir"`

	// FrontMatter settings for static site generators
	FrontMatter FrontMatterConfig `json:"frontMatter"`

	// IncludeExamples generates example inputs/outputs
	IncludeExamples bool `json:"includeExamples"`

	// IncludeDiagrams generates Mermaid diagrams for rule flow
	IncludeDiagrams bool `json:"includeDiagrams"`

	// GroupByNamespace organizes output by namespace
	GroupByNamespace bool `json:"groupByNamespace"`
}

// FrontMatterConfig for static site generator front matter.
type FrontMatterConfig struct {
	// Author name for generated docs
	Author string `json:"author"`

	// BaseURL for cross-references
	BaseURL string `json:"baseUrl"`

	// Tags to add to all pages
	Tags []string `json:"tags"`

	// Category for organization
	Category string `json:"category"`

	// Draft marks pages as draft
	Draft bool `json:"draft"`
}

func (p *MarkdownPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "markdown",
		Type:        plugin.TypeFunction, // Extends Q with doc generation
		Version:     "1.0.0",
		Description: "Generate human-readable markdown documentation from CUE policies. Supports GitHub, Hugo, Astro, and Docusaurus formats.",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		Capabilities: []string{
			"docs.generate",
			"docs.export",
		},
	}
}

func (p *MarkdownPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = MarkdownConfig{
		OutputFormat:     "github",
		OutputDir:        "./docs/policies",
		IncludeExamples:  true,
		IncludeDiagrams:  true,
		GroupByNamespace: true,
	}

	if v, ok := config["outputFormat"].(string); ok {
		p.config.OutputFormat = v
	}
	if v, ok := config["outputDir"].(string); ok {
		p.config.OutputDir = v
	}
	if v, ok := config["templateDir"].(string); ok {
		p.config.TemplateDir = v
	}
	if v, ok := config["includeExamples"].(bool); ok {
		p.config.IncludeExamples = v
	}
	if v, ok := config["includeDiagrams"].(bool); ok {
		p.config.IncludeDiagrams = v
	}
	if v, ok := config["groupByNamespace"].(bool); ok {
		p.config.GroupByNamespace = v
	}

	// Parse front matter config
	if fm, ok := config["frontMatter"].(map[string]interface{}); ok {
		if v, ok := fm["author"].(string); ok {
			p.config.FrontMatter.Author = v
		}
		if v, ok := fm["baseUrl"].(string); ok {
			p.config.FrontMatter.BaseURL = v
		}
		if v, ok := fm["category"].(string); ok {
			p.config.FrontMatter.Category = v
		}
		if v, ok := fm["draft"].(bool); ok {
			p.config.FrontMatter.Draft = v
		}
		if v, ok := fm["tags"].([]interface{}); ok {
			for _, tag := range v {
				if s, ok := tag.(string); ok {
					p.config.FrontMatter.Tags = append(p.config.FrontMatter.Tags, s)
				}
			}
		}
	}

	// Load templates
	if err := p.loadTemplates(); err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}

	// Initialize CUE context
	p.ctx = cuecontext.New()

	return nil
}

func (p *MarkdownPlugin) Health(ctx context.Context) error {
	if p.templates == nil {
		return fmt.Errorf("templates not loaded")
	}
	return nil
}

func (p *MarkdownPlugin) Close() error {
	return nil
}

// GenerateFromFile generates documentation for a single policy file.
func (p *MarkdownPlugin) GenerateFromFile(ctx context.Context, policyPath string) (*GeneratedDoc, error) {
	content, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}

	return p.GenerateFromContent(ctx, string(content), filepath.Base(policyPath))
}

// GenerateFromContent generates documentation from CUE content.
func (p *MarkdownPlugin) GenerateFromContent(ctx context.Context, content, sourceName string) (*GeneratedDoc, error) {
	// Parse CUE
	value := p.ctx.CompileString(content, cue.Filename(sourceName))
	if value.Err() != nil {
		return nil, fmt.Errorf("parsing CUE: %w", value.Err())
	}

	// Extract policy information
	policy, err := p.extractPolicy(value)
	if err != nil {
		return nil, fmt.Errorf("extracting policy: %w", err)
	}

	// Generate markdown
	doc, err := p.renderPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("rendering: %w", err)
	}

	return doc, nil
}

// GeneratePolicySet generates documentation for a policy set (multiple files).
func (p *MarkdownPlugin) GeneratePolicySet(ctx context.Context, paths []string) ([]*GeneratedDoc, error) {
	var docs []*GeneratedDoc

	for _, path := range paths {
		doc, err := p.GenerateFromFile(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("generating %s: %w", path, err)
		}
		docs = append(docs, doc)
	}

	// Generate index page
	index, err := p.generateIndex(docs)
	if err != nil {
		return nil, fmt.Errorf("generating index: %w", err)
	}
	docs = append([]*GeneratedDoc{index}, docs...)

	return docs, nil
}

// WriteToDir writes generated docs to the output directory.
func (p *MarkdownPlugin) WriteToDir(docs []*GeneratedDoc, outputDir string) error {
	if outputDir == "" {
		outputDir = p.config.OutputDir
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	for _, doc := range docs {
		// Create subdirectory if needed
		docPath := filepath.Join(outputDir, doc.Path)
		docDir := filepath.Dir(docPath)
		if err := os.MkdirAll(docDir, 0755); err != nil {
			return fmt.Errorf("creating dir %s: %w", docDir, err)
		}

		// Write file
		if err := os.WriteFile(docPath, []byte(doc.Content), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", docPath, err)
		}
	}

	return nil
}

// GeneratedDoc represents a generated documentation file.
type GeneratedDoc struct {
	// Path relative to output directory
	Path string

	// Content of the markdown file
	Content string

	// Title for the document
	Title string

	// Namespace of the policy
	Namespace string

	// PolicyName
	PolicyName string
}

// PolicyInfo contains extracted information from a CUE policy.
type PolicyInfo struct {
	APIVersion  string
	Kind        string
	Name        string
	Namespace   string
	Version     string
	Description string
	Labels      map[string]string
	Annotations map[string]string

	// Target information
	Target TargetInfo

	// Rules
	Rules []RuleInfo

	// Priority configuration
	Priority PriorityInfo

	// Input schema
	InputSchema *SchemaInfo

	// Generated metadata
	GeneratedAt time.Time
	SourceFile  string
}

type TargetInfo struct {
	System      string
	Environment string
	Pipeline    string
}

type RuleInfo struct {
	ID          string
	Description string
	Severity    string
	Category    string
	Condition   string
	Message     string
	Remediation string
	References  []string
	Examples    []ExampleInfo
}

type ExampleInfo struct {
	Description string
	Input       string
	Expected    string
}

type PriorityInfo struct {
	Mode    string
	Default int
	Rules   map[string]int
}

type SchemaInfo struct {
	Fields []FieldInfo
}

type FieldInfo struct {
	Name        string
	Type        string
	Required    bool
	Description string
	Default     string
}

// extractPolicy extracts policy information from a CUE value.
func (p *MarkdownPlugin) extractPolicy(value cue.Value) (*PolicyInfo, error) {
	policy := &PolicyInfo{
		GeneratedAt: time.Now().UTC(),
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
	}

	// Extract apiVersion
	if v := value.LookupPath(cue.ParsePath("apiVersion")); v.Exists() {
		policy.APIVersion, _ = v.String()
	}

	// Extract kind
	if v := value.LookupPath(cue.ParsePath("kind")); v.Exists() {
		policy.Kind, _ = v.String()
	}

	// Extract metadata
	if meta := value.LookupPath(cue.ParsePath("metadata")); meta.Exists() {
		if v := meta.LookupPath(cue.ParsePath("name")); v.Exists() {
			policy.Name, _ = v.String()
		}
		if v := meta.LookupPath(cue.ParsePath("namespace")); v.Exists() {
			policy.Namespace, _ = v.String()
		}
		if v := meta.LookupPath(cue.ParsePath("version")); v.Exists() {
			policy.Version, _ = v.String()
		}
		if v := meta.LookupPath(cue.ParsePath("description")); v.Exists() {
			policy.Description, _ = v.String()
		}

		// Labels
		if labels := meta.LookupPath(cue.ParsePath("labels")); labels.Exists() {
			iter, _ := labels.Fields()
			for iter.Next() {
				key := iter.Label()
				val, _ := iter.Value().String()
				policy.Labels[key] = val
			}
		}

		// Annotations
		if annotations := meta.LookupPath(cue.ParsePath("annotations")); annotations.Exists() {
			iter, _ := annotations.Fields()
			for iter.Next() {
				key := iter.Label()
				val, _ := iter.Value().String()
				policy.Annotations[key] = val
			}
		}
	}

	// Extract target
	if target := value.LookupPath(cue.ParsePath("spec.target")); target.Exists() {
		if v := target.LookupPath(cue.ParsePath("system")); v.Exists() {
			policy.Target.System, _ = v.String()
		}
		if v := target.LookupPath(cue.ParsePath("environment")); v.Exists() {
			policy.Target.Environment, _ = v.String()
		}
		if v := target.LookupPath(cue.ParsePath("pipeline")); v.Exists() {
			policy.Target.Pipeline, _ = v.String()
		}
	}

	// Extract rules
	if rules := value.LookupPath(cue.ParsePath("spec.rules")); rules.Exists() {
		iter, _ := rules.List()
		for iter.Next() {
			rule := p.extractRule(iter.Value())
			policy.Rules = append(policy.Rules, rule)
		}
	}

	// Extract priority
	if priority := value.LookupPath(cue.ParsePath("spec.priority")); priority.Exists() {
		policy.Priority = p.extractPriority(priority)
	}

	return policy, nil
}

func (p *MarkdownPlugin) extractRule(value cue.Value) RuleInfo {
	rule := RuleInfo{}

	if v := value.LookupPath(cue.ParsePath("id")); v.Exists() {
		rule.ID, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("description")); v.Exists() {
		rule.Description, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("severity")); v.Exists() {
		rule.Severity, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("category")); v.Exists() {
		rule.Category, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("message")); v.Exists() {
		rule.Message, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("remediation")); v.Exists() {
		rule.Remediation, _ = v.String()
	}

	// Extract condition (format for display)
	if v := value.LookupPath(cue.ParsePath("condition")); v.Exists() {
		rule.Condition = fmt.Sprintf("%v", v)
	}

	// Extract references
	if refs := value.LookupPath(cue.ParsePath("references")); refs.Exists() {
		iter, _ := refs.List()
		for iter.Next() {
			if ref, err := iter.Value().String(); err == nil {
				rule.References = append(rule.References, ref)
			}
		}
	}

	return rule
}

func (p *MarkdownPlugin) extractPriority(value cue.Value) PriorityInfo {
	priority := PriorityInfo{
		Rules: make(map[string]int),
	}

	if v := value.LookupPath(cue.ParsePath("mode")); v.Exists() {
		priority.Mode, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("default")); v.Exists() {
		d, _ := v.Int64()
		priority.Default = int(d)
	}

	if rules := value.LookupPath(cue.ParsePath("rules")); rules.Exists() {
		iter, _ := rules.Fields()
		for iter.Next() {
			key := iter.Label()
			val, _ := iter.Value().Int64()
			priority.Rules[key] = int(val)
		}
	}

	return priority
}

// renderPolicy renders a policy to markdown.
func (p *MarkdownPlugin) renderPolicy(policy *PolicyInfo) (*GeneratedDoc, error) {
	tmpl, ok := p.templates[p.config.OutputFormat]
	if !ok {
		tmpl = p.templates["github"] // Default
	}

	data := &templateData{
		Policy:      policy,
		Config:      p.config,
		FrontMatter: p.generateFrontMatter(policy),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	// Determine output path
	path := p.policyPath(policy)

	return &GeneratedDoc{
		Path:       path,
		Content:    buf.String(),
		Title:      policy.Name,
		Namespace:  policy.Namespace,
		PolicyName: policy.Name,
	}, nil
}

func (p *MarkdownPlugin) policyPath(policy *PolicyInfo) string {
	name := policy.Name
	if name == "" {
		name = "policy"
	}

	// Sanitize name - remove special characters, keep only alphanumeric and hyphens
	var sanitized strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sanitized.WriteRune(r)
		} else if r == ' ' {
			sanitized.WriteRune('-')
		}
		// Skip all other special characters
	}
	name = strings.ToLower(sanitized.String())

	// Clean up multiple consecutive hyphens
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")

	if name == "" {
		name = "policy"
	}

	if p.config.GroupByNamespace && policy.Namespace != "" {
		return filepath.Join(policy.Namespace, name+".md")
	}

	return name + ".md"
}

func (p *MarkdownPlugin) generateFrontMatter(policy *PolicyInfo) string {
	if p.config.OutputFormat == "plain" || p.config.OutputFormat == "github" {
		return ""
	}

	fm := map[string]interface{}{
		"title":       policy.Name,
		"description": policy.Description,
		"date":        policy.GeneratedAt.Format("2006-01-02"),
	}

	if policy.Namespace != "" {
		fm["namespace"] = policy.Namespace
	}
	if policy.Version != "" {
		fm["version"] = policy.Version
	}

	// Add configured front matter
	if p.config.FrontMatter.Author != "" {
		fm["author"] = p.config.FrontMatter.Author
	}
	if p.config.FrontMatter.Category != "" {
		fm["category"] = p.config.FrontMatter.Category
	}
	if p.config.FrontMatter.Draft {
		fm["draft"] = true
	}

	// Merge tags
	tags := append([]string{}, p.config.FrontMatter.Tags...)
	if policy.Target.Environment != "" {
		tags = append(tags, policy.Target.Environment)
	}
	if len(tags) > 0 {
		fm["tags"] = tags
	}

	// Format specific additions
	switch p.config.OutputFormat {
	case "hugo":
		fm["type"] = "policy"
		fm["layout"] = "policy"
	case "astro":
		fm["layout"] = "../../layouts/PolicyLayout.astro"
	case "docusaurus":
		fm["sidebar_position"] = 1
		if len(policy.Labels) > 0 {
			fm["keywords"] = mapValues(policy.Labels)
		}
	}

	out, _ := yaml.Marshal(fm)
	return "---\n" + string(out) + "---\n\n"
}

func (p *MarkdownPlugin) generateIndex(docs []*GeneratedDoc) (*GeneratedDoc, error) {
	tmpl, ok := p.templates["index"]
	if !ok {
		return nil, fmt.Errorf("index template not found")
	}

	// Group docs by namespace
	byNamespace := make(map[string][]*GeneratedDoc)
	for _, doc := range docs {
		ns := doc.Namespace
		if ns == "" {
			ns = "default"
		}
		byNamespace[ns] = append(byNamespace[ns], doc)
	}

	data := struct {
		Title       string
		Description string
		Docs        []*GeneratedDoc
		ByNamespace map[string][]*GeneratedDoc
		Config      MarkdownConfig
		GeneratedAt time.Time
	}{
		Title:       "Policy Documentation",
		Description: "Auto-generated documentation for Q policies",
		Docs:        docs,
		ByNamespace: byNamespace,
		Config:      p.config,
		GeneratedAt: time.Now().UTC(),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	path := "_index.md"
	if p.config.OutputFormat == "docusaurus" {
		path = "index.md"
	}

	return &GeneratedDoc{
		Path:    path,
		Content: buf.String(),
		Title:   "Policy Index",
	}, nil
}

func (p *MarkdownPlugin) loadTemplates() error {
	p.templates = make(map[string]*template.Template)

	funcs := template.FuncMap{
		"upper":         strings.ToUpper,
		"lower":         strings.ToLower,
		"title":         strings.Title,
		"join":          strings.Join,
		"severityBadge": severityBadge,
		"severityIcon":  severityIcon,
		"formatCode":    formatCode,
	}

	// Load embedded templates
	formats := []string{"github", "hugo", "astro", "docusaurus", "plain", "index"}
	for _, format := range formats {
		content, err := templatesFS.ReadFile("templates/" + format + ".tmpl")
		if err != nil {
			return fmt.Errorf("reading %s template: %w", format, err)
		}

		tmpl, err := template.New(format).Funcs(funcs).Parse(string(content))
		if err != nil {
			return fmt.Errorf("parsing %s template: %w", format, err)
		}
		p.templates[format] = tmpl
	}

	// Load custom templates if configured (override embedded)
	if p.config.TemplateDir != "" {
		entries, err := os.ReadDir(p.config.TemplateDir)
		if err != nil {
			return fmt.Errorf("reading template dir: %w", err)
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmpl") {
				continue
			}

			name := strings.TrimSuffix(entry.Name(), ".tmpl")
			content, err := os.ReadFile(filepath.Join(p.config.TemplateDir, entry.Name()))
			if err != nil {
				return fmt.Errorf("reading %s: %w", entry.Name(), err)
			}

			tmpl, err := template.New(name).Funcs(funcs).Parse(string(content))
			if err != nil {
				return fmt.Errorf("parsing %s: %w", entry.Name(), err)
			}
			p.templates[name] = tmpl
		}
	}

	return nil
}

type templateData struct {
	Policy      *PolicyInfo
	Config      MarkdownConfig
	FrontMatter string
}

// Template helper functions
func severityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	case "info":
		return "🔵"
	default:
		return "⚪"
	}
}

func severityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "❌"
	case "high":
		return "⚠️"
	case "medium":
		return "⚡"
	case "low":
		return "ℹ️"
	default:
		return "📝"
	}
}

func formatCode(code string) string {
	return "```cue\n" + code + "\n```"
}

func mapValues(m map[string]string) []string {
	vals := make([]string, 0, len(m))
	for _, v := range m {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	return vals
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &MarkdownPlugin{}
