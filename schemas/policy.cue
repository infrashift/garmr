// schemas/policy.cue
// Package policy defines the core schema for Garmr policies.
// All policies must conform to these schemas for validation and evaluation.
package policy

// Policy is the top-level unit of evaluation.
// Each policy targets specific resources and defines rules to enforce.
#Policy: {
	apiVersion: "policy.garmr.io/v1"
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
	// Resource selectors (OR semantics - matches any).
	// A plain string is shorthand for {kind: <string>}.
	resources: [...(string | #ResourceSelector)]

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

	// Field matching (supports equals, pattern, comparison, etc.)
	match?:    #MatchExpr

	// Cross-field comparison
	compare?:  #CompareExpr

	// Existence checks
	exists?: string  // Path must exist and be non-null
	absent?: string  // Path must not exist or be null

	// Collection operators
	contains?: #ContainsExpr
	forEach?:  #ForEachExpr

	// Builtin function call
	"func"?: #FuncCallExpr
}

// MatchExpr matches a field at a given path against various conditions.
// Exactly one condition operator must be specified alongside `path`.
#MatchExpr: {
	// Path to the field in the input (dot-notation)
	path: string

	// --- Equality ---
	// Exact value match (type-aware comparison)
	equals?: _

	// --- Existence ---
	// Check if the field exists (true) or is absent (false)
	exists?: bool

	// --- Comparison (numeric) ---
	greaterThan?:        number
	greaterThanOrEqual?: number
	lessThan?:           number
	lessThanOrEqual?:    number

	// --- String matching ---
	// Regex pattern match
	pattern?: string
	// Substring containment
	contains?: string
	// Prefix check
	hasPrefix?: string
	// Suffix check
	hasSuffix?: string

	// --- Set membership ---
	// Value must be one of the listed values
	in?: [...]
	// Value must NOT be one of the listed values
	notIn?: [...]

	// --- Set validation (array fields) ---
	// Array must have no duplicate values
	unique?: bool
	// Array of objects must have no duplicate values for this field
	uniqueBy?: string
	// Array must be sorted in the given order
	sorted?: "asc" | "desc"
	// Array must contain all listed values (superset check)
	containsAll?: [...]
	// Every array element must be from the listed set (subset check)
	subsetOf?: [...]

	// --- Collection ---
	// Length constraints for arrays or strings
	length?: #LengthExpr

	// --- Semantic versioning ---
	semver?: #SemverExpr

	// --- Date/time ---
	datetime?: #DatetimeExpr
}

// LengthExpr defines length constraints.
#LengthExpr: {
	equals?:             int
	greaterThan?:        int
	greaterThanOrEqual?: int
	lessThan?:           int
	lessThanOrEqual?:    int
	min?:                int
	max?:                int
}

// SemverExpr defines semantic version constraints.
#SemverExpr: {
	greaterThan?:        string
	greaterThanOrEqual?: string
	lessThan?:           string
	lessThanOrEqual?:    string
	equals?:             string
	// Constraint expression, comma-separated AND conditions.
	// Supports >=, <=, >, <, =, ^ (same major), ~ (same major.minor),
	// e.g. ">=1.0.0,<2.0.0" or "^1.2.3".
	constraint?: string
}

// DatetimeExpr defines date/time constraints.
#DatetimeExpr: {
	// Field timestamp must be after this time
	after?: string
	// Field timestamp must be before this time
	before?: string
	// Field timestamp must be at or after this time
	afterOrEqual?: string
	// Field timestamp must be at or before this time
	beforeOrEqual?: string
	// Field must be within N days of now
	withinDays?: int
	// Field must be within N hours of now
	withinHours?: int
	// Field must have at least N days until expiry
	expiresAfterDays?: int
	// Field must not be expired (i.e., is in the future)
	notExpired?: bool
}

// CompareExpr compares two resolved values.
#CompareExpr: {
	left:  #Value
	op:    #CompareOp
	right: #Value
}

#CompareOp:
	"==" | "!=" |
	"<" | "<=" | ">" | ">=" |
	"eq" | "ne" | "neq" |
	"gt" | "gte" | "lt" | "lte" |
	"in" | "not_in" | "notIn" |
	"contains" | "hasPrefix" | "hasSuffix" |
	"matches" | "startsWith" | "endsWith" |
	"semverGt" | "semverGte" | "semverLt" | "semverLte" | "semverEq" |
	"after" | "before" | "afterOrEqual" | "beforeOrEqual"

// Value represents a value source in comparisons and function calls.
#Value: {
	// Reference to input field (dot-notation path)
	path?: string

	// Literal value
	literal?: _

	// Function call result
	func?: #FuncCall
}

// FuncCall invokes a built-in function within a Value context.
#FuncCall: {
	name: #BuiltinFunc
	args: [...#Value]
}

// FuncCallExpr invokes a built-in function as a standalone expression.
// The function result is evaluated for truthiness, or compared with `expect`.
#FuncCallExpr: {
	// Function name
	name: #BuiltinFunc

	// Arguments (literal values or input path references)
	args: [...]

	// Expected result value (if omitted, truthiness is used)
	expect?: _

	// Bind the result to a variable name for use in message templates
	bind?: string
}

// BuiltinFunc defines all available built-in functions.
#BuiltinFunc:
	// Core
	"len" | "count" |
	// Aggregates
	"sum" | "min" | "max" | "avg" |
	// String manipulation
	"lower" | "upper" | "trim" | "trimPrefix" | "trimSuffix" |
	"split" | "join" | "contains" | "startsWith" | "endsWith" |
	"matches" | "regex" | "format" |
	// Encoding
	"base64Decode" | "base64Encode" |
	// Time / duration
	"now" | "duration" | "parseTime" |
	// Type checking
	"typeOf" | "isType" |
	// Object / map
	"hasKey" | "keys" | "values" |
	// Network / CIDR
	"cidr" | "cidrContains" | "cidrOverlap" | "ipVersion" |
	// Kubernetes units
	"unitsParse" |
	// Lookup / path
	"lookup" | "jsonPath" |
	// Array operations
	"flatten" | "unique" | "sort" | "filter" |
	// Semver
	"semver"

// ContainsExpr checks if a collection contains a value.
#ContainsExpr: {
	// Path to the collection or string field
	path:   string
	// Single value that must be present
	value?: _
	// All listed values must be present
	all?:   [..._]
	// At least one of the listed values must be present
	any?:   [..._]
}

// ForEachExpr iterates over a collection and evaluates a condition per item.
#ForEachExpr: {
	// Path to the array field in input
	path: string

	// Variable name for current item (default: "item")
	as: string | *"item"

	// Condition to evaluate for each element (expression object)
	condition: _

	// Mode: "all" = every item must pass, "any" = at least one must pass
	mode: "all" | "any" | *"all"

	// Whether an empty array passes (true, the default) or fails (false)
	allowEmpty?: bool
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
	apiVersion: "policy.garmr.io/v1"
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
