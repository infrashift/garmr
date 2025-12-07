// schemas/policy.cue
// Package policy defines the core schema for Q Policy Agent policies.
// All policies must conform to these schemas for validation and evaluation.
package policy

import "time"

// Policy is the top-level unit of evaluation.
// Each policy targets specific resources and defines rules to enforce.
#Policy: {
	apiVersion: "policy.q.io/v1"
	kind:       "Policy"
	metadata:   #Metadata
	spec:       #PolicySpec
}

// Metadata contains identifying information for policies.
#Metadata: {
	// name must be lowercase alphanumeric with hyphens
	name: string & =~"^[a-z][a-z0-9-]{0,62}$"
	
	// namespace for logical grouping (default: "default")
	namespace: string | *"default"
	
	// labels for filtering and selection
	labels: [string]: string
	
	// annotations for non-identifying metadata
	annotations: [string]: string
	
	// Allow extension fields
	...
}

// PolicySpec defines the policy behavior.
#PolicySpec: {
	// Human-readable description
	description?: string
	
	// What this policy applies to
	target: #Target
	
	// Rules to evaluate (at least one required)
	rules: [#Rule, ...#Rule]
	
	// How violations are handled
	enforcement: #Enforcement
	
	// Optional dependencies on other policies
	requires?: [...#PolicyRef]
	
	// Evaluation configuration
	evaluation?: #EvaluationConfig
}

// EvaluationConfig controls how rules are evaluated.
#EvaluationConfig: {
	// Order in which rules are evaluated
	// - "priority": Sort by priority field (lower first), then definition order
	// - "severity": Sort by severity (critical first), then definition order
	// - "definition": Evaluate in the order rules are defined (default)
	// - "priority-then-severity": Sort by priority, then severity within same priority
	order: #EvaluationOrder | *"priority"
	
	// Stop evaluation on first failure (fail-fast mode)
	// Useful for expensive evaluations or when first failure is sufficient
	failFast?: bool | *false
	
	// Only evaluate rules matching these categories
	includeCategories?: [...string]
	
	// Skip rules matching these categories
	excludeCategories?: [...string]
	
	// Only evaluate rules with these tags
	includeTags?: [...string]
	
	// Skip rules with these tags
	excludeTags?: [...string]
	
	// Maximum number of rules to evaluate (0 = unlimited)
	maxRules?: int & >=0 | *0
	
	// Timeout for entire policy evaluation
	timeout?: string  // Duration string, e.g., "30s", "5m"
}

// Target specifies what resources a policy applies to.
#Target: {
	// Resource selectors (OR semantics - matches any)
	resources: [...#ResourceSelector]
	
	// Pre-conditions that must be true for policy to apply
	conditions?: [...#Condition]
}

// ResourceSelector identifies resources by type and attributes.
#ResourceSelector: {
	// API group (empty string for core, "*" for any)
	apiGroup: string | *"*"
	
	// Resource kind ("*" for any)
	kind: string | *"*"
	
	// Specific resource names
	names?: [...string]
	
	// Label selector
	labels?: [string]: string
	
	// Annotation selector
	annotations?: [string]: string
	
	// Namespace selector
	namespaces?: [...string]
}

// Rule is an individual policy check.
#Rule: {
	// Unique identifier within policy (e.g., "SEC-001")
	id: string & =~"^[A-Z]{2,6}-[0-9]{3,4}$"
	
	// Human-readable description
	description: string
	
	// Severity level
	severity: #Severity
	
	// Priority for evaluation order (lower = evaluated first)
	// If not specified, rules are evaluated in definition order
	// Common patterns:
	//   - 10, 20, 30, 40... (allows insertion)
	//   - 100, 200, 300... (for major groupings)
	//   - 1, 2, 3... (for strict ordering)
	// Rules with same priority maintain definition order
	priority?: int & >=0 & <=9999
	
	// The constraint expression
	expr: #Expression
	
	// Custom violation message (supports template variables)
	message?: string
	
	// Documentation URL
	url?: string
	
	// Remediation guidance
	remediation?: string
	
	// Category for grouping in reports (e.g., "security", "compliance", "promotion")
	category?: string
	
	// Tags for filtering (e.g., ["pci-dss", "soc2", "slsa"])
	tags?: [...string]
	
	// Whether to continue evaluation after this rule fails
	// Default: true (continue evaluating other rules)
	// Set to false for critical gates that should halt evaluation
	continueOnFail?: bool | *true
}

// Severity levels from informational to critical.
#Severity: "critical" | "high" | "medium" | "low" | "info"

// SeverityWeight maps severity to numeric weight for scoring.
#SeverityWeight: {
	critical: 100
	high:     75
	medium:   50
	low:      25
	info:     0
}

// EvaluationOrder defines how rules are sorted for evaluation.
#EvaluationOrder: "priority" | "severity" | "definition" | "priority-then-severity"

// Default priority values by category (for use in policies)
#DefaultPriority: {
	// Promotion/chain validation should run first
	promotion:   100
	// Security checks next
	security:    200
	// Quality gates
	quality:     300
	// Compliance checks
	compliance:  400
	// Best practices / recommendations last
	advisory:    500
}

// Expression is the core constraint logic using a composable structure.
// Exactly one field must be set.
#Expression: {
	// Logical operators
	all?: [...#Expression]  // AND: all must pass
	any?: [...#Expression]  // OR: at least one must pass
	not?: #Expression       // NOT: must fail
	
	// Comparison operators
	match?:    #MatchExpr
	compare?:  #CompareExpr
	
	// Existence checks
	exists?: string  // Path must exist and be non-null
	absent?: string  // Path must not exist or be null
	
	// Collection operators
	contains?: #ContainsExpr
	forEach?:  #ForEachExpr
	
	// Reference to external rule or data
	ref?: string
	
	// Raw CUE expression (advanced usage)
	cue?: string
	
	// Ensure exactly one is set
	_oneOf: true & (
		(all != _|_) |
		(any != _|_) |
		(not != _|_) |
		(match != _|_) |
		(compare != _|_) |
		(exists != _|_) |
		(absent != _|_) |
		(contains != _|_) |
		(forEach != _|_) |
		(ref != _|_) |
		(cue != _|_)
	)
}

// MatchExpr matches a field against a pattern.
#MatchExpr: {
	// Path to the field (JSONPath syntax)
	path: string
	
	// Pattern to match (regex)
	pattern: string
	
	// Match options
	ignoreCase?: bool
}

// CompareExpr compares two values.
#CompareExpr: {
	left:  #Value
	op:    #CompareOp
	right: #Value
}

#CompareOp: "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "not_in" | "matches" | "startsWith" | "endsWith"

// Value represents a value in comparisons.
#Value: {
	// Reference to input field
	path?: string
	
	// Literal value
	literal?: _
	
	// Function call
	func?: #FuncCall
	
	// Environment variable
	env?: string
	
	// Data reference
	data?: string
}

// FuncCall invokes a built-in function.
#FuncCall: {
	name: #BuiltinFunc
	args: [...#Value]
}

// BuiltinFunc defines available functions.
#BuiltinFunc:
	"len" |
	"count" |
	"sum" |
	"min" |
	"max" |
	"avg" |
	"lower" |
	"upper" |
	"trim" |
	"split" |
	"join" |
	"contains" |
	"startsWith" |
	"endsWith" |
	"regex" |
	"now" |
	"duration" |
	"parseTime" |
	"format" |
	"base64Decode" |
	"base64Encode" |
	"jsonPath" |
	"semver" |
	"cidr" |
	"lookup"

// ContainsExpr checks if a collection contains a value.
#ContainsExpr: {
	path:   string
	value?: _
	all?:   [..._]
	any?:   [..._]
}

// ForEachExpr iterates over a collection.
#ForEachExpr: {
	// Path to collection
	collection: string
	
	// Variable name for current item
	as: string | *"item"
	
	// Index variable name
	index?: string
	
	// Expression to evaluate for each item
	expr: #Expression
	
	// Mode: all must pass or any must pass
	mode: "all" | "any" | *"all"
}

// Condition for policy applicability.
#Condition: {
	expr: #Expression
}

// Enforcement defines how violations are handled.
#Enforcement: {
	// Primary action
	action: #EnforcementAction
	
	// Dry run mode (log but don't enforce)
	dryRun: bool | *false
	
	// Exceptions to enforcement
	exceptions?: [...#Exception]
	
	// Webhook for external decision
	webhook?: #Webhook
}

#EnforcementAction: "deny" | "warn" | "audit"

// Exception allows bypassing enforcement for specific cases.
#Exception: {
	name:   string
	reason: string
	match:  #ResourceSelector
	
	// Expiration (RFC3339)
	expiry?: string
	
	// Approval chain
	approvedBy?: [...string]
	
	// Jira/issue tracker reference
	ticket?: string
}

// Webhook for external policy decisions.
#Webhook: {
	url:     string & =~"^https?://"
	timeout: string | *"5s"
	
	// Retry configuration
	retry?: {
		attempts: int & >=0 & <=5 | *3
		backoff:  string | *"1s"
	}
	
	// TLS configuration
	tls?: {
		insecure?: bool
		ca?:       string  // Base64 encoded CA cert
	}
}

// PolicyRef references another policy.
#PolicyRef: {
	name:      string
	namespace: string | *"default"
}

// PolicySet groups policies for atomic evaluation.
#PolicySet: {
	apiVersion: "policy.q.io/v1"
	kind:       "PolicySet"
	metadata:   #Metadata
	spec: {
		// Policies in this set
		policies: [...#Policy | #PolicyRef]
		
		// Evaluation mode
		mode: "all" | "any" | *"all"
		
		// Stop on first failure
		failFast: bool | *false
	}
}

// DataSource defines external data for policy decisions.
#DataSource: {
	apiVersion: "policy.q.io/v1"
	kind:       "DataSource"
	metadata:   #Metadata
	spec: {
		// Source type
		type: "inline" | "http" | "file" | "git" | "s3"
		
		// Refresh interval
		refresh: string | *"5m"
		
		// Inline data
		data?: _
		
		// Remote URL
		url?: string
		
		// Git-specific
		git?: {
			url:    string
			ref:    string | *"main"
			path:   string | *"/"
			sparse: [...string]
		}
		
		// S3-specific  
		s3?: {
			bucket: string
			key:    string
			region: string
		}
		
		// Authentication
		auth?: #AuthConfig
	}
}

// AuthConfig for authenticated data sources.
#AuthConfig: {
	type: "none" | "basic" | "bearer" | "mtls" | "aws" | "gcp" | "oidc"
	
	// Secret reference (namespace/name)
	secretRef?: string
	
	// Direct credentials (not recommended for production)
	credentials?: {
		username?: string
		password?: string
		token?:    string
	}
}

// EvaluationResult is the output of policy evaluation.
#EvaluationResult: {
	decision: "allow" | "deny" | "warn"
	
	results: [...#RuleResult]
	
	summary: {
		total:    int
		passed:   int
		failed:   int
		warnings: int
		score:    float & >=0 & <=100
	}
}

#RuleResult: {
	policyName:      string
	policyNamespace: string
	ruleId:          string
	severity:        #Severity
	passed:          bool
	message:         string
	bindings: [string]: _
}
