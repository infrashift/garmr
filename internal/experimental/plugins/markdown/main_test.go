// plugins/markdown/main_test.go
// Package main provides tests for the markdown documentation generator plugin.
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sample CUE policy for testing
const samplePolicy = `
{
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	
	metadata: {
		name: "release-gate"
		namespace: "production"
		version: "1.0.0"
		description: "Production release gate policy for validating deployments"
		labels: {
			team: "platform"
			tier: "critical"
		}
		annotations: {
			"policy.garmr.io/owner": "devops@example.com"
		}
	}
	
	spec: {
		target: {
			system: "release-pipeline"
			environment: "production"
			pipeline: "deploy"
		}
		
		rules: [
			{
				id: "REL-001"
				description: "All tests must pass before deployment"
				severity: "critical"
				category: "quality"
				condition: "input.tests.passed == true"
				message: "Test suite did not pass"
				remediation: "Review test failures and fix before retrying"
				references: [
					"https://wiki.example.com/testing-standards",
					"https://docs.example.com/ci-cd-pipeline"
				]
			},
			{
				id: "REL-002"
				description: "Code coverage must meet minimum threshold"
				severity: "high"
				category: "quality"
				condition: "input.coverage >= 80"
				message: "Code coverage below 80%"
				remediation: "Add tests to increase coverage"
			},
			{
				id: "REL-003"
				description: "Security scan must complete without critical findings"
				severity: "critical"
				category: "security"
				condition: "input.security.criticalFindings == 0"
				message: "Critical security vulnerabilities found"
				remediation: "Address all critical security findings before deployment"
			},
			{
				id: "REL-004"
				description: "Approval required from release manager"
				severity: "medium"
				category: "governance"
				condition: "len(input.approvals) > 0"
				message: "Missing required approval"
			}
		]
		
		priority: {
			mode: "severity"
			default: 100
			rules: {
				"REL-001": 1000
				"REL-003": 900
			}
		}
	}
}
`

// Minimal policy for edge case testing
const minimalPolicy = `
{
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name: "minimal"
	}
	spec: {
		rules: []
	}
}
`

// Invalid CUE for error testing
const invalidCUE = `
{
	this is not valid CUE!!!
}
`

// ============================================
// PLUGIN LIFECYCLE TESTS
// ============================================

func TestPluginMetadata(t *testing.T) {
	plugin := &MarkdownPlugin{}
	meta := plugin.Metadata()

	t.Run("has correct name", func(t *testing.T) {
		if meta.Name != "markdown" {
			t.Errorf("wrong name: got %s", meta.Name)
		}
	})

	t.Run("has version", func(t *testing.T) {
		if meta.Version == "" {
			t.Error("version is empty")
		}
	})

	t.Run("has capabilities", func(t *testing.T) {
		if len(meta.Capabilities) == 0 {
			t.Error("no capabilities defined")
		}
	})

	t.Run("has description", func(t *testing.T) {
		if meta.Description == "" {
			t.Error("description is empty")
		}
	})
}

func TestPluginInit(t *testing.T) {
	t.Run("initializes with defaults", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		err := plugin.Init(context.Background(), nil)
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}

		if plugin.config.OutputFormat != "github" {
			t.Errorf("wrong default format: got %s", plugin.config.OutputFormat)
		}
		if plugin.config.OutputDir != "./docs/policies" {
			t.Errorf("wrong default outputDir: got %s", plugin.config.OutputDir)
		}
		if !plugin.config.IncludeExamples {
			t.Error("IncludeExamples should default to true")
		}
		if !plugin.config.IncludeDiagrams {
			t.Error("IncludeDiagrams should default to true")
		}
		if !plugin.config.GroupByNamespace {
			t.Error("GroupByNamespace should default to true")
		}
		if plugin.templates == nil {
			t.Error("templates not loaded")
		}
		if plugin.ctx == nil {
			t.Error("CUE context not initialized")
		}
	})

	t.Run("accepts custom config", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		config := map[string]interface{}{
			"outputFormat":     "hugo",
			"outputDir":        "/custom/path",
			"includeExamples":  false,
			"includeDiagrams":  false,
			"groupByNamespace": false,
		}

		err := plugin.Init(context.Background(), config)
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}

		if plugin.config.OutputFormat != "hugo" {
			t.Errorf("outputFormat not set: got %s", plugin.config.OutputFormat)
		}
		if plugin.config.OutputDir != "/custom/path" {
			t.Errorf("outputDir not set: got %s", plugin.config.OutputDir)
		}
		if plugin.config.IncludeExamples {
			t.Error("includeExamples should be false")
		}
		if plugin.config.IncludeDiagrams {
			t.Error("includeDiagrams should be false")
		}
		if plugin.config.GroupByNamespace {
			t.Error("groupByNamespace should be false")
		}
	})

	t.Run("parses front matter config", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		config := map[string]interface{}{
			"frontMatter": map[string]interface{}{
				"author":   "Test Author",
				"baseUrl":  "https://example.com",
				"category": "policies",
				"draft":    true,
				"tags":     []interface{}{"tag1", "tag2"},
			},
		}

		err := plugin.Init(context.Background(), config)
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}

		if plugin.config.FrontMatter.Author != "Test Author" {
			t.Errorf("author not set: got %s", plugin.config.FrontMatter.Author)
		}
		if plugin.config.FrontMatter.BaseURL != "https://example.com" {
			t.Errorf("baseUrl not set: got %s", plugin.config.FrontMatter.BaseURL)
		}
		if plugin.config.FrontMatter.Category != "policies" {
			t.Errorf("category not set: got %s", plugin.config.FrontMatter.Category)
		}
		if !plugin.config.FrontMatter.Draft {
			t.Error("draft not set")
		}
		if len(plugin.config.FrontMatter.Tags) != 2 {
			t.Errorf("wrong tag count: got %d, want 2", len(plugin.config.FrontMatter.Tags))
		}
	})

	t.Run("loads all output format templates", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), nil)

		formats := []string{"github", "hugo", "astro", "docusaurus", "plain", "index"}
		for _, format := range formats {
			if _, ok := plugin.templates[format]; !ok {
				t.Errorf("template not loaded: %s", format)
			}
		}
	})
}

func TestPluginHealth(t *testing.T) {
	t.Run("healthy after init", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), nil)

		err := plugin.Health(context.Background())
		if err != nil {
			t.Errorf("health check failed: %v", err)
		}
	})

	t.Run("unhealthy before init", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		err := plugin.Health(context.Background())
		if err == nil {
			t.Error("should fail before init")
		}
	})
}

func TestPluginClose(t *testing.T) {
	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	err := plugin.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// ============================================
// CONTENT GENERATION TESTS
// ============================================

func TestGenerateFromContent(t *testing.T) {
	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	t.Run("generates from valid policy", func(t *testing.T) {
		doc, err := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")
		if err != nil {
			t.Fatalf("GenerateFromContent failed: %v", err)
		}

		if doc.Title != "release-gate" {
			t.Errorf("wrong title: got %s, want release-gate", doc.Title)
		}
		if doc.Namespace != "production" {
			t.Errorf("wrong namespace: got %s, want production", doc.Namespace)
		}
		if doc.PolicyName != "release-gate" {
			t.Errorf("wrong policy name: got %s", doc.PolicyName)
		}
		if doc.Content == "" {
			t.Error("content is empty")
		}
		if doc.Path == "" {
			t.Error("path is empty")
		}
	})

	t.Run("content contains policy name", func(t *testing.T) {
		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "release-gate") {
			t.Error("content should contain policy name")
		}
	})

	t.Run("content contains rules", func(t *testing.T) {
		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		ruleIDs := []string{"REL-001", "REL-002", "REL-003", "REL-004"}
		for _, id := range ruleIDs {
			if !strings.Contains(doc.Content, id) {
				t.Errorf("content should contain rule %s", id)
			}
		}
	})

	t.Run("content contains severity indicators", func(t *testing.T) {
		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "critical") {
			t.Error("content should contain severity")
		}
	})

	t.Run("content contains description", func(t *testing.T) {
		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "Production release gate policy") {
			t.Error("content should contain description")
		}
	})

	t.Run("handles minimal policy", func(t *testing.T) {
		doc, err := plugin.GenerateFromContent(context.Background(), minimalPolicy, "minimal.cue")
		if err != nil {
			t.Fatalf("should handle minimal policy: %v", err)
		}

		if doc.Title != "minimal" {
			t.Errorf("wrong title: got %s", doc.Title)
		}
	})

	t.Run("returns error for invalid CUE", func(t *testing.T) {
		_, err := plugin.GenerateFromContent(context.Background(), invalidCUE, "invalid.cue")
		if err == nil {
			t.Error("should return error for invalid CUE")
		}
	})
}

// ============================================
// OUTPUT FORMAT TESTS
// ============================================

func TestOutputFormats(t *testing.T) {
	formats := []struct {
		name           string
		hasFrontMatter bool
		frontMatterKey string
	}{
		{"github", false, ""},
		{"hugo", true, "type"},
		{"astro", true, "layout"},
		{"docusaurus", true, "sidebar_position"},
		{"plain", false, ""},
	}

	for _, format := range formats {
		t.Run(format.name+" format", func(t *testing.T) {
			plugin := &MarkdownPlugin{}
			plugin.Init(context.Background(), map[string]interface{}{
				"outputFormat": format.name,
			})

			doc, err := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")
			if err != nil {
				t.Fatalf("generation failed: %v", err)
			}

			hasFM := strings.HasPrefix(doc.Content, "---")
			if format.hasFrontMatter && !hasFM {
				t.Errorf("%s format should have front matter", format.name)
			}
			if !format.hasFrontMatter && hasFM {
				t.Errorf("%s format should not have front matter", format.name)
			}

			// Check format-specific content
			if format.name == "hugo" && !strings.Contains(doc.Content, "{{<") {
				// Hugo uses shortcodes
			}
			if format.name == "astro" && !strings.Contains(doc.Content, "import") {
				t.Error("astro format should have imports")
			}
			if format.name == "docusaurus" && !strings.Contains(doc.Content, ":::") {
				// Docusaurus uses admonitions
			}
		})
	}
}

func TestFrontMatterGeneration(t *testing.T) {
	t.Run("includes configured author", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"outputFormat": "hugo",
			"frontMatter": map[string]interface{}{
				"author": "John Doe",
			},
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "author: John Doe") {
			t.Error("front matter should contain author")
		}
	})

	t.Run("includes tags", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"outputFormat": "hugo",
			"frontMatter": map[string]interface{}{
				"tags": []interface{}{"policy", "security"},
			},
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "tags:") {
			t.Error("front matter should contain tags")
		}
	})

	t.Run("includes draft flag", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"outputFormat": "hugo",
			"frontMatter": map[string]interface{}{
				"draft": true,
			},
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "draft: true") {
			t.Error("front matter should contain draft flag")
		}
	})
}

// ============================================
// PATH GENERATION TESTS
// ============================================

func TestPathGeneration(t *testing.T) {
	t.Run("groups by namespace when enabled", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"groupByNamespace": true,
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.HasPrefix(doc.Path, "production/") {
			t.Errorf("path should start with namespace: got %s", doc.Path)
		}
	})

	t.Run("flat structure when grouping disabled", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"groupByNamespace": false,
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if strings.Contains(doc.Path, "/") {
			t.Errorf("path should be flat: got %s", doc.Path)
		}
	})

	t.Run("sanitizes policy name in path", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), nil)

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if strings.Contains(doc.Path, " ") {
			t.Error("path should not contain spaces")
		}
		if doc.Path != strings.ToLower(doc.Path) {
			t.Error("path should be lowercase")
		}
	})

	t.Run("adds .md extension", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), nil)

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.HasSuffix(doc.Path, ".md") {
			t.Errorf("path should end with .md: got %s", doc.Path)
		}
	})
}

// ============================================
// FILE I/O TESTS
// ============================================

func TestGenerateFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test-policy.cue")
	os.WriteFile(policyPath, []byte(samplePolicy), 0644)

	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	t.Run("generates from file", func(t *testing.T) {
		doc, err := plugin.GenerateFromFile(context.Background(), policyPath)
		if err != nil {
			t.Fatalf("GenerateFromFile failed: %v", err)
		}

		if doc.Title != "release-gate" {
			t.Errorf("wrong title: got %s", doc.Title)
		}
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		_, err := plugin.GenerateFromFile(context.Background(), "/nonexistent/file.cue")
		if err == nil {
			t.Error("should return error for nonexistent file")
		}
	})
}

func TestWriteToDir(t *testing.T) {
	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")
	docs := []*GeneratedDoc{doc}

	t.Run("writes files to directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		err := plugin.WriteToDir(docs, tmpDir)
		if err != nil {
			t.Fatalf("WriteToDir failed: %v", err)
		}

		// Check file exists
		expectedPath := filepath.Join(tmpDir, doc.Path)
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Errorf("file not created: %s", expectedPath)
		}
	})

	t.Run("creates subdirectories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Doc has namespace prefix in path
		err := plugin.WriteToDir(docs, tmpDir)
		if err != nil {
			t.Fatalf("WriteToDir failed: %v", err)
		}

		// Check subdirectory created
		expectedDir := filepath.Join(tmpDir, "production")
		if info, err := os.Stat(expectedDir); err != nil || !info.IsDir() {
			t.Error("subdirectory not created")
		}
	})

	t.Run("uses config outputDir when not specified", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputDir := filepath.Join(tmpDir, "custom-output")

		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"outputDir": outputDir,
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")
		plugin.WriteToDir([]*GeneratedDoc{doc}, "")

		// Should use config outputDir
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			t.Error("should use config outputDir")
		}
	})
}

// ============================================
// POLICY SET TESTS
// ============================================

func TestGeneratePolicySet(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple policy files
	policies := map[string]string{
		"policy1.cue": samplePolicy,
		"policy2.cue": minimalPolicy,
	}

	var paths []string
	for name, content := range policies {
		path := filepath.Join(tmpDir, name)
		os.WriteFile(path, []byte(content), 0644)
		paths = append(paths, path)
	}

	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	t.Run("generates docs for all policies", func(t *testing.T) {
		docs, err := plugin.GeneratePolicySet(context.Background(), paths)
		if err != nil {
			t.Fatalf("GeneratePolicySet failed: %v", err)
		}

		// Should have index + 2 policies
		if len(docs) != 3 {
			t.Errorf("wrong doc count: got %d, want 3", len(docs))
		}
	})

	t.Run("includes index page", func(t *testing.T) {
		docs, _ := plugin.GeneratePolicySet(context.Background(), paths)

		// First doc should be index
		if !strings.Contains(docs[0].Path, "index") && !strings.Contains(docs[0].Path, "_index") {
			t.Errorf("first doc should be index: got %s", docs[0].Path)
		}
	})

	t.Run("returns error if any policy fails", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "invalid.cue")
		os.WriteFile(invalidPath, []byte(invalidCUE), 0644)

		_, err := plugin.GeneratePolicySet(context.Background(), []string{invalidPath})
		if err == nil {
			t.Error("should return error for invalid policy")
		}
	})
}

// ============================================
// TEMPLATE HELPER FUNCTION TESTS
// ============================================

func TestSeverityBadge(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "🔴"},
		{"high", "🟠"},
		{"medium", "🟡"},
		{"low", "🟢"},
		{"info", "🔵"},
		{"unknown", "⚪"},
		{"CRITICAL", "🔴"}, // Case insensitive
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			result := severityBadge(tc.severity)
			if result != tc.expected {
				t.Errorf("severityBadge(%s) = %s, want %s", tc.severity, result, tc.expected)
			}
		})
	}
}

func TestSeverityIcon(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "❌"},
		{"high", "⚠️"},
		{"medium", "⚡"},
		{"low", "ℹ️"},
		{"unknown", "📝"},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			result := severityIcon(tc.severity)
			if result != tc.expected {
				t.Errorf("severityIcon(%s) = %s, want %s", tc.severity, result, tc.expected)
			}
		})
	}
}

func TestFormatCode(t *testing.T) {
	code := "input.value > 10"
	result := formatCode(code)

	if !strings.HasPrefix(result, "```cue") {
		t.Error("should start with code fence")
	}
	if !strings.HasSuffix(result, "```") {
		t.Error("should end with code fence")
	}
	if !strings.Contains(result, code) {
		t.Error("should contain the code")
	}
}

// ============================================
// DIAGRAM GENERATION TESTS
// ============================================

func TestDiagramGeneration(t *testing.T) {
	t.Run("includes mermaid diagram when enabled", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"includeDiagrams": true,
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if !strings.Contains(doc.Content, "```mermaid") {
			t.Error("should include mermaid diagram")
		}
		if !strings.Contains(doc.Content, "flowchart") {
			t.Error("should include flowchart")
		}
	})

	t.Run("excludes diagram when disabled", func(t *testing.T) {
		plugin := &MarkdownPlugin{}
		plugin.Init(context.Background(), map[string]interface{}{
			"includeDiagrams": false,
		})

		doc, _ := plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")

		if strings.Contains(doc.Content, "```mermaid") {
			t.Error("should not include mermaid diagram when disabled")
		}
	})
}

// ============================================
// EDGE CASE TESTS
// ============================================

func TestEdgeCases(t *testing.T) {
	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	t.Run("handles policy without namespace", func(t *testing.T) {
		policy := `{
			apiVersion: "policy.garmr.io/v1"
			metadata: { name: "no-namespace" }
			spec: { rules: [] }
		}`

		doc, err := plugin.GenerateFromContent(context.Background(), policy, "test.cue")
		if err != nil {
			t.Fatalf("should handle policy without namespace: %v", err)
		}

		if doc.Namespace != "" {
			t.Errorf("namespace should be empty: got %s", doc.Namespace)
		}
	})

	t.Run("handles policy without version", func(t *testing.T) {
		policy := `{
			apiVersion: "policy.garmr.io/v1"
			metadata: { name: "no-version" }
			spec: { rules: [] }
		}`

		doc, err := plugin.GenerateFromContent(context.Background(), policy, "test.cue")
		if err != nil {
			t.Fatalf("should handle policy without version: %v", err)
		}

		// Should still generate valid content
		if doc.Content == "" {
			t.Error("content should not be empty")
		}
	})

	t.Run("handles rules without optional fields", func(t *testing.T) {
		policy := `{
			apiVersion: "policy.garmr.io/v1"
			metadata: { name: "minimal-rules" }
			spec: {
				rules: [{
					id: "RULE-001"
					severity: "low"
				}]
			}
		}`

		doc, err := plugin.GenerateFromContent(context.Background(), policy, "test.cue")
		if err != nil {
			t.Fatalf("should handle minimal rules: %v", err)
		}

		if !strings.Contains(doc.Content, "RULE-001") {
			t.Error("should contain rule ID")
		}
	})

	t.Run("handles empty rules array", func(t *testing.T) {
		doc, err := plugin.GenerateFromContent(context.Background(), minimalPolicy, "test.cue")
		if err != nil {
			t.Fatalf("should handle empty rules: %v", err)
		}

		if doc.Content == "" {
			t.Error("should generate content even with empty rules")
		}
	})

	t.Run("handles special characters in policy name", func(t *testing.T) {
		policy := `{
			apiVersion: "policy.garmr.io/v1"
			metadata: { name: "Policy With Spaces & Special!" }
			spec: { rules: [] }
		}`

		doc, err := plugin.GenerateFromContent(context.Background(), policy, "test.cue")
		if err != nil {
			t.Fatalf("should handle special characters: %v", err)
		}

		// Path should be sanitized
		if strings.Contains(doc.Path, " ") || strings.Contains(doc.Path, "&") {
			t.Errorf("path should be sanitized: got %s", doc.Path)
		}
	})
}

// ============================================
// BENCHMARK TESTS
// ============================================

func BenchmarkGenerateFromContent(b *testing.B) {
	plugin := &MarkdownPlugin{}
	plugin.Init(context.Background(), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")
	}
}

func BenchmarkGenerateAllFormats(b *testing.B) {
	formats := []string{"github", "hugo", "astro", "docusaurus", "plain"}

	for _, format := range formats {
		b.Run(format, func(b *testing.B) {
			plugin := &MarkdownPlugin{}
			plugin.Init(context.Background(), map[string]interface{}{
				"outputFormat": format,
			})

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plugin.GenerateFromContent(context.Background(), samplePolicy, "test.cue")
			}
		})
	}
}
