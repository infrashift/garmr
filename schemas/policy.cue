// schemas/policy.cue
// Package policy defines the schema for Garmr policies. The engine unifies
// every policy with #Policy at load; `garmr validate` and `cue vet` use the
// same file.
package policy

import "time"

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
	namespace: string & =~"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$" | *"default"

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

	// Rules to evaluate (at least one required). Rule ids must be unique
	// within a policy.
	rules: [#Rule, ...#Rule]

	// How violations are handled
	enforcement: #Enforcement

	// Evaluation configuration
	evaluation?: #EvaluationConfig
}

// EvaluationConfig controls how rules are evaluated.
#EvaluationConfig: {
	// Order in which rules are evaluated
	// - "priority": by priority field (lower first; rules without one last),
	//   then definition order (default)
	// - "severity": by severity (critical first), then definition order
	// - "definition": in the order rules are defined
	// - "priority-then-severity": by priority, then severity within a priority
	order: #EvaluationOrder | *"priority"

	// Stop evaluation on first failure (fail-fast mode)
	failFast?: bool

	// Only evaluate rules matching these categories
	includeCategories?: [...string]

	// Skip rules matching these categories
	excludeCategories?: [...string]

	// Only evaluate rules with these tags
	includeTags?: [...string]

	// Skip rules with these tags
	excludeTags?: [...string]

	// Maximum number of rules to evaluate (0 = unlimited)
	maxRules?: int & >=0

	// Deadline for the whole evaluation, as a Go duration ("250ms", "30s").
	// The smallest timeout among the matched policies applies.
	timeout?: time.Duration
}

// Target specifies what resources a policy applies to.
#Target: {
	// Resource selectors (OR semantics - matches any).
	// A plain string is shorthand for {kind: <string>}.
	resources: [...(string | #ResourceSelector)]
}

// ResourceSelector identifies resources by type and attributes. Patterns are
// case-insensitive; "*" matches any run of characters.
#ResourceSelector: {
	// API group, matched against the group part of the input's apiVersion
	// ("apps" for "apps/v1"). "" is the core group ("v1"); "*" is any group.
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
	// Identifier, unique within the policy (e.g., "SEC-001").
	id: string & =~"^[A-Za-z][A-Za-z0-9_-]{0,63}$"

	// Human-readable description
	description: string

	// Severity level
	severity: #Severity

	// Priority for evaluation order (lower = evaluated first). Rules with the
	// same priority keep definition order.
	priority?: int & >=0 & <=9999

	// The rule applies only when this holds; otherwise it passes as not
	// applicable. "When the pod is in production, it needs 2 replicas":
	//   when: match: {path: "metadata.labels.env", equals: "prod"}
	//   expr: match: {path: "spec.replicas", greaterThanOrEqual: 2}
	// A `when` that cannot be evaluated fails the rule.
	when?: #Expression

	// The check this rule performs.
	expr: #Expression

	// Custom violation message. Placeholders:
	//   {{.name}}  a binding: `length`, `version`, `datetime`, `count`, or a
	//              `func` bind name
	//   {{path}}   an input field, or a forEach alias path ({{c.name}});
	//              {{_index}} is the element's position
	// A message that refers to a forEach alias is rendered once per failing
	// element. A placeholder that does not resolve is left as written.
	message?: string

	// Documentation URL
	url?: string

	// Remediation guidance
	remediation?: string

	// Category for grouping in reports (e.g., "security", "compliance", "promotion")
	category?: string

	// Tags for filtering (e.g., ["pci-dss", "soc2", "slsa"])
	tags?: [...string]
}

// Severity levels from informational to critical.
#Severity: "critical" | "high" | "medium" | "low" | "info"

// EvaluationOrder defines how rules are sorted for evaluation.
#EvaluationOrder: "priority" | "severity" | "definition" | "priority-then-severity"

// Expression is a check. Exactly one operator must be set; combine checks
// with all/any/not.
//
// Paths are dot-separated field names: `spec.containers`. Quote a key that
// contains dots or other punctuation (`metadata.labels."app.kubernetes.io/name"`)
// and index lists with `[N]` (`spec.containers[0].image`). `[*]` projects:
// `spec.containers[*].cpu` is the list of every container's cpu (null where a
// container has none), ready for `sum`, `len`, `unique` or the set operators.
// Inside a forEach, a path starting with the alias reads the current element,
// and `_index` is its position.
//
// A missing field fails a check. An operand of the wrong type (a string where
// a number is required, an unparseable semver or datetime) is an evaluation
// error: it fails the rule even under `not`.
#Expression: {
	// Logical operators
	all?: [...#Expression] // AND: all must pass
	any?: [...#Expression] // OR: at least one must pass
	not?:                  #Expression // NOT: must fail

	// Check a field at a path
	match?: #MatchExpr

	// Compare two values
	compare?: #CompareExpr

	// Check each element of a list
	forEach?: #ForEachExpr

	// Call a builtin function
	func?: #FuncCallExpr
}

// MatchExpr checks the field at `path`. At least one operator must be set;
// when several are set, every one must pass (AND semantics). The same holds
// inside `length`, `semver` and `datetime`, e.g.
// `datetime: {after: X, before: Y}` is a range check.
#MatchExpr: {
	// Path to the field in the input
	path: string

	// --- Presence ---
	// true: the field exists and is not null. false: it is absent or null.
	exists?: bool

	// --- Equality ---
	// Strict, JSON-typed equality: numbers compare by value (1 == 1.0),
	// every other pair must have the same type ("1" != 1).
	equals?: _

	// --- Comparison (numeric) ---
	greaterThan?:        number
	greaterThanOrEqual?: number
	lessThan?:           number
	lessThanOrEqual?:    number

	// --- String matching ---
	// Regular expression (RE2) match
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

	// --- Set validation (list fields) ---
	// List must have no duplicate values
	unique?: bool
	// List of objects must have no duplicate values for this field path
	uniqueBy?: string
	// List must be sorted in the given order
	sorted?: "asc" | "desc"
	// List must contain all listed values (superset check)
	containsAll?: [...]
	// List must contain at least one of the listed values
	containsAny?: [...]
	// Every list element must be from the listed set (subset check)
	subsetOf?: [...]

	// --- Collection ---
	// Length constraints for lists or strings (strings count characters)
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

// DatetimeExpr defines date/time constraints. Operands accept RFC3339,
// "2006-01-02" and a few other common layouts, or "now".
#DatetimeExpr: {
	// Field timestamp must be after this time
	after?: string
	// Field timestamp must be before this time
	before?: string
	// Field timestamp must be at or after this time
	afterOrEqual?: string
	// Field timestamp must be at or before this time
	beforeOrEqual?: string
	// Field must be within N days of now, in either direction
	withinDays?: int
	// Field must be within N hours of now, in either direction
	withinHours?: int
	// Field must be at least N days in the future
	expiresAfterDays?: int
	// true: field must be in the future. false: it must be in the past.
	notExpired?: bool
}

// CompareExpr compares two resolved values.
#CompareExpr: {
	left:  #Value
	op:    #CompareOp
	right: #Value
}

// CompareOp is a comparison operator.
//   - == != : strict equality, as for match.equals
//   - < <= > >= : two numbers, or two strings (lexical)
//   - in notIn : membership of left in the list on the right
//   - contains : left list contains right, or left string contains right
//   - subsetOf : every key/value of the left object is in the right object
//                (a label selector within labels), or every element of the
//                left list is in the right list
//   - hasPrefix hasSuffix matches : string operators (matches: RE2)
//   - semver* : semantic versions; after/before/... : datetimes
#CompareOp:
	"==" | "!=" |
	"<" | "<=" | ">" | ">=" |
	"in" | "notIn" |
	"contains" | "subsetOf" | "hasPrefix" | "hasSuffix" | "matches" |
	"semverGt" | "semverGte" | "semverLt" | "semverLte" | "semverEq" |
	"after" | "before" | "afterOrEqual" | "beforeOrEqual"

// Value is an operand: exactly one of an input path, a literal, or a builtin
// call. A path that does not exist resolves to null.
#Value: {
	// Reference to an input field
	path?: string

	// Literal value
	literal?: _

	// Builtin call result
	func?: #FuncCall
}

// FuncCall invokes a builtin function within a Value.
#FuncCall: {
	name: #BuiltinFunc
	args?: [...#Value]
}

// FuncCallExpr invokes a builtin as a check. The result must be truthy (not
// false, 0, "", [], {} or null), or equal `expect` when it is set.
#FuncCallExpr: {
	name: #BuiltinFunc
	args?: [...#Value]

	// Expected result value (if omitted, truthiness is used)
	expect?: _

	// Bind the result to a name for use in message templates
	bind?: string
}

// BuiltinFunc names the builtin functions.
#BuiltinFunc:
	// Core
	"len" |
	// Aggregates
	"sum" | "min" | "max" | "avg" |
	// Strings
	"lower" | "upper" | "trim" | "trimPrefix" | "trimSuffix" |
	"split" | "join" | "matches" | "format" |
	// Encoding
	"base64Decode" | "base64Encode" |
	// Time / duration
	"now" | "duration" | "parseTime" |
	// Type checking
	"typeOf" | "isType" |
	// Objects
	"hasKey" | "keys" | "values" | "lookup" |
	// Network / CIDR
	"cidrContains" | "cidrOverlap" | "ipVersion" |
	// Kubernetes units
	"unitsParse" |
	// Lists
	"flatten" | "unique" | "sort" | "filter"

// ForEachExpr checks every element of a list.
#ForEachExpr: {
	// Path to the list
	path: string

	// Name the condition uses for the current element
	as: string & =~"^[A-Za-z][A-Za-z0-9_]*$" | *"item"

	// Check applied to each element. Required: the loader rejects a forEach
	// without one. (Declared optional because a required field here would be
	// a structural cycle through #Expression.)
	condition?: #Expression

	// Only the elements for which this holds are checked (and counted);
	// the alias is in scope. "Of the deployments with the
	// same name as this service, ...":
	//   where: compare: {left: {path: "d.metadata.name"}, op: "==", right: {path: "s.metadata.name"}}
	// allowEmpty, mode "any" and count apply to the selected elements.
	where?: #Expression

	// "all" (the default): every element must pass. "any": at least one.
	mode?: "all" | "any"

	// Whether an empty list passes (true, the default) or fails (false)
	allowEmpty?: bool

	// Count the elements that pass the condition and check the count, e.g.
	// `count: {lessThanOrEqual: 1}` for "at most one". Replaces mode and
	// allowEmpty; an empty list counts 0.
	count?: #LengthExpr
}

// Enforcement defines how violations are handled.
#Enforcement: {
	// Primary action
	action: #EnforcementAction

	// Dry run mode (report, but never deny)
	dryRun: bool | *false

	// Exceptions to enforcement
	exceptions?: [...#Exception]
}

#EnforcementAction: "deny" | "warn" | "audit"

// Exception skips the whole policy for inputs its selector matches. The
// selector must narrow something: an exception matching everything would
// disable the policy.
#Exception: {
	name:   string
	reason: string
	match:  #ResourceSelector

	// Expiration (RFC3339). After this instant the exception no longer applies.
	expiry?: time.Time

	// Approval chain
	approvedBy?: [...string]

	// Jira/issue tracker reference
	ticket?: string
}
