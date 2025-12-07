// schemas/markdown_plugin.cue
// Markdown Documentation Generator Plugin Configuration
package config

// MarkdownPluginConfig configures the documentation generator.
#MarkdownPluginConfig: {
	// Output format for generated documentation
	// - github: GitHub-flavored markdown
	// - hugo: Hugo static site (with front matter)
	// - astro: Astro framework (with components)
	// - docusaurus: Docusaurus docs (with admonitions)
	// - plain: Plain markdown without front matter
	outputFormat: "github" | "hugo" | "astro" | "docusaurus" | "plain" | *"github"
	
	// Output directory for generated files
	outputDir: string | *"./docs/policies"
	
	// Custom template directory (optional)
	// Templates override built-in templates
	templateDir: string | *""
	
	// Front matter settings for static site generators
	frontMatter: #FrontMatterConfig
	
	// Include example inputs/outputs in documentation
	includeExamples: bool | *true
	
	// Include Mermaid diagrams for rule flow visualization
	includeDiagrams: bool | *true
	
	// Organize output by namespace subdirectories
	groupByNamespace: bool | *true
}

#FrontMatterConfig: {
	// Author name for generated docs
	author: string | *""
	
	// Base URL for cross-references
	baseUrl: string | *""
	
	// Tags to add to all generated pages
	tags: [...string] | *[]
	
	// Category for organization
	category: string | *"policies"
	
	// Mark pages as draft
	draft: bool | *false
}

// Plugin entry for markdown generator
#MarkdownPluginEntry: {
	enabled: bool | *true
	type:    "function"
	config:  #MarkdownPluginConfig
}

// Example configurations

// GitHub README documentation
_githubDocsConfig: #MarkdownPluginConfig & {
	outputFormat:     "github"
	outputDir:        "./docs/policies"
	includeDiagrams:  true
	groupByNamespace: true
}

// Hugo static site documentation
_hugoDocsConfig: #MarkdownPluginConfig & {
	outputFormat: "hugo"
	outputDir:    "./content/policies"
	frontMatter: {
		author:   "Policy Team"
		category: "policies"
		tags: ["policy", "compliance"]
	}
	includeDiagrams: true
}

// Astro documentation site
_astroDocsConfig: #MarkdownPluginConfig & {
	outputFormat: "astro"
	outputDir:    "./src/content/policies"
	frontMatter: {
		author: "DevOps Team"
	}
	includeDiagrams: true
}

// Docusaurus documentation
_docusaurusConfig: #MarkdownPluginConfig & {
	outputFormat: "docusaurus"
	outputDir:    "./docs/policies"
	frontMatter: {
		category: "Policy Reference"
		tags: ["api", "policy"]
	}
}

// Minimal plain markdown
_plainConfig: #MarkdownPluginConfig & {
	outputFormat:     "plain"
	outputDir:        "./docs"
	includeDiagrams:  false
	includeExamples:  false
	groupByNamespace: false
}
