// schemas/policyset.cue
// Policy Set Schema
// Allows organizing related policies across multiple files
package policy

// PolicySet groups related policies that should be evaluated together.
// Use policy sets when:
// 1. A logical policy is too large for one file
// 2. You want to share definitions across policies
// 3. You need to version/release policies as a unit
#PolicySet: {
	apiVersion: "policy.q.io/v1"
	kind:       "PolicySet"
	metadata:   #PolicySetMetadata
	spec:       #PolicySetSpec
}

#PolicySetMetadata: {
	// Name of the policy set
	name: string & =~"^[a-z][a-z0-9-]{0,62}$"
	
	// Namespace for all policies in the set
	namespace: string | *"default"
	
	// Version of the policy set
	version?: string
	
	// Labels for the entire set
	labels: [string]: string
	
	// Annotations
	annotations: [string]: string
}

#PolicySetSpec: {
	// Human-readable description
	description?: string
	
	// Files included in this policy set (relative to manifest)
	// If empty, all .cue files in directory are included
	include?: [...string]
	
	// Files to exclude
	exclude?: [...string]
	
	// Shared definitions available to all policies in set
	// These are unified with each policy before evaluation
	definitions?: {...}
	
	// Shared input schema for all policies
	inputSchema?: {...}
	
	// Evaluation order for policies in the set
	// "parallel" - evaluate all concurrently
	// "sequential" - evaluate in order listed
	// "dependency" - evaluate based on requires fields
	evaluationOrder: "parallel" | "sequential" | "dependency" | *"parallel"
	
	// Policy references (for explicit ordering)
	policies?: [...#PolicyRef]
	
	// Shared enforcement settings (can be overridden per-policy)
	enforcement?: {
		action:  "deny" | "warn" | "audit"
		dryRun?: bool
	}
}

#PolicyRef: {
	// File path relative to manifest
	file: string
	
	// Override name (uses filename if not specified)
	name?: string
	
	// Override enforcement for this policy
	enforcement?: {
		action:  "deny" | "warn" | "audit"
		dryRun?: bool
	}
	
	// Dependencies on other policies in the set
	requires?: [...string]
	
	// Conditions for when this policy applies
	when?: {...}
}

// ============================================
// EXAMPLE POLICY SET
// ============================================

// Example: Release Pipeline Policy Set
// Organizes DTAP policies into a cohesive unit

_examplePolicySet: #PolicySet & {
	apiVersion: "policy.q.io/v1"
	kind:       "PolicySet"
	metadata: {
		name:      "release-pipeline"
		namespace: "release"
		version:   "2.0.0"
		labels: {
			"category": "release-management"
			"team":     "platform"
		}
		annotations: {
			"docs": "https://wiki.example.com/release-policies"
		}
	}
	spec: {
		description: """
			Complete DTAP release pipeline policy set.
			Enforces progressive quality gates from development to production.
			"""
		
		// Include specific files in order
		include: [
			"definitions.cue",      // Shared definitions
			"input-schema.cue",     // Common input schema
			"dev-release.cue",      // Development policy
			"test-release.cue",     // Test policy
			"acc-release.cue",      // Acceptance policy
			"prod-release.cue",     // Production policy
		]
		
		exclude: [
			"*_test.cue",
			"testdata/*",
		]
		
		// Shared definitions available to all policies
		definitions: {
			// Common severity mappings
			_severityWeight: {
				critical: 100
				high:     75
				medium:   50
				low:      25
				info:     0
			}
			
			// Common approval groups
			_approvalGroups: {
				dev:        ["developers"]
				test:       ["developers", "qa"]
				acceptance: ["qa-leads", "product-owners"]
				prod:       ["release-managers"]
			}
			
			// CVE thresholds by environment
			_cveThresholds: {
				dev:        {critical: 999, high: 999, medium: 999}
				test:       {critical: 10,  high: 50,  medium: 999}
				acceptance: {critical: 0,   high: 5,   medium: 50}
				prod:       {critical: 0,   high: 0,   medium: 10}
			}
		}
		
		// Evaluation: sequential ensures promotion chain is validated
		evaluationOrder: "sequential"
		
		// Explicit policy ordering with dependencies
		policies: [
			{
				file: "dev-release.cue"
				name: "release-gate-dev"
				enforcement: action: "audit"
			},
			{
				file: "test-release.cue"
				name: "release-gate-test"
				enforcement: action: "warn"
				requires: ["release-gate-dev"]  // Dev must pass first
			},
			{
				file: "acc-release.cue"
				name: "release-gate-acc"
				enforcement: action: "deny"
				requires: ["release-gate-test"]
			},
			{
				file: "prod-release.cue"
				name: "release-gate-prod"
				enforcement: action: "deny"
				requires: ["release-gate-acc"]
			},
		]
		
		// Default enforcement (overridden per-policy above)
		enforcement: action: "deny"
	}
}

// ============================================
// POLICY SET DIRECTORY STRUCTURE EXAMPLE
// ============================================

// Example directory layout:
//
// /policies/
// └── release/
//     └── pipeline/
//         ├── policyset.cue          # Manifest (this file)
//         ├── definitions.cue        # Shared definitions
//         ├── input-schema.cue       # Common input schema
//         ├── dev-release.cue        # Dev environment policy
//         ├── test-release.cue       # Test environment policy
//         ├── acc-release.cue        # Acceptance environment policy
//         ├── prod-release.cue       # Production environment policy
//         └── testdata/              # Test fixtures (excluded)
//             └── valid-release.json
//
// Loading behavior:
// 1. Loader finds policyset.cue manifest
// 2. Loads and validates manifest against #PolicySet schema
// 3. Loads each file in spec.include order
// 4. Unifies spec.definitions with each policy
// 5. Registers policies with engine
// 6. During evaluation, respects evaluationOrder and requires

// ============================================
// MULTI-FILE POLICY EXAMPLE
// ============================================

// When a single policy is too large, split into multiple files
// and use CUE's import/unification:

// File: rules-security.cue
_securityRules: [...#Rule] & [
	{id: "SEC-001", description: "SBOM required", /*...*/},
	{id: "SEC-002", description: "CVE scan required", /*...*/},
]

// File: rules-quality.cue  
_qualityRules: [...#Rule] & [
	{id: "QA-001", description: "Tests must pass", /*...*/},
	{id: "QA-002", description: "Coverage threshold", /*...*/},
]

// File: policy.cue (main policy file)
// import (
//     "example.com/policies/release:security"
//     "example.com/policies/release:quality"
// )
// 
// productionPolicy: #Policy & {
//     spec: {
//         rules: security._securityRules + quality._qualityRules
//     }
// }
