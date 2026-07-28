package engine

import (
	"context"
	"fmt"
	"strings"

	"cuelang.org/go/cue"
)

// evaluateExpression evaluates a CUE expression against input.
func (e *Engine) evaluateExpression(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	// Check for 'forEach' (array iteration)
	if forEachVal := expr.LookupPath(cue.ParsePath("forEach")); forEachVal.Exists() {
		return e.evaluateForEach(ctx, forEachVal, input)
	}

	// Check for 'all' (AND)
	if allVal := expr.LookupPath(cue.ParsePath("all")); allVal.Exists() {
		iter, _ := allVal.List()
		for iter.Next() {
			passed, b, msg := e.evaluateExpression(ctx, iter.Value(), input)
			for k, v := range b {
				bindings[k] = v
			}
			if !passed {
				return false, bindings, msg
			}
		}
		return true, bindings, ""
	}

	// Check for 'any' (OR)
	if anyVal := expr.LookupPath(cue.ParsePath("any")); anyVal.Exists() {
		iter, _ := anyVal.List()
		var lastMsg string
		for iter.Next() {
			passed, b, msg := e.evaluateExpression(ctx, iter.Value(), input)
			if passed {
				for k, v := range b {
					bindings[k] = v
				}
				return true, bindings, ""
			}
			lastMsg = msg
		}
		return false, bindings, lastMsg
	}

	// Check for 'not'
	if notVal := expr.LookupPath(cue.ParsePath("not")); notVal.Exists() {
		passed, b, _ := e.evaluateExpression(ctx, notVal, input)
		for k, v := range b {
			bindings[k] = v
		}
		return !passed, bindings, ""
	}

	// Check for 'exists'
	if existsVal := expr.LookupPath(cue.ParsePath("exists")); existsVal.Exists() {
		path, _ := existsVal.String()
		fieldVal := input.LookupPath(cue.ParsePath(path))
		exists := fieldVal.Exists() && fieldVal.Kind() != cue.NullKind
		if !exists {
			return false, bindings, fmt.Sprintf("field '%s' does not exist", path)
		}
		return true, bindings, ""
	}

	// Check for 'absent'
	if absentVal := expr.LookupPath(cue.ParsePath("absent")); absentVal.Exists() {
		path, _ := absentVal.String()
		fieldVal := input.LookupPath(cue.ParsePath(path))
		absent := !fieldVal.Exists() || fieldVal.Kind() == cue.NullKind
		if !absent {
			return false, bindings, fmt.Sprintf("field '%s' should not exist", path)
		}
		return true, bindings, ""
	}

	// Check for 'contains' (collection contains check)
	if containsVal := expr.LookupPath(cue.ParsePath("contains")); containsVal.Exists() {
		return e.evaluateContainsExpr(containsVal, input)
	}

	// Check for 'match'
	if matchVal := expr.LookupPath(cue.ParsePath("match")); matchVal.Exists() {
		return e.evaluateMatch(matchVal, input)
	}

	// Check for 'compare'
	if compareVal := expr.LookupPath(cue.ParsePath("compare")); compareVal.Exists() {
		return e.evaluateCompare(ctx, compareVal, input)
	}

	// Check for 'func' (builtin function call)
	if funcVal := expr.LookupPath(cue.ParsePath("func")); funcVal.Exists() {
		return e.evaluateFunc(ctx, funcVal, input)
	}

	// 'ref' is not supported (removed from the schema). Top-level uses are
	// rejected at compile time; this backstop catches refs nested inside
	// all/any/not, which would otherwise silently pass through the default
	// unify branch below.
	if refVal := expr.LookupPath(cue.ParsePath("ref")); refVal.Exists() {
		return false, bindings, "expr 'ref' is not supported"
	}

	// Default: the expression is a raw CUE constraint over input fields, e.g.
	// `expr: {spec: replicas: <=3}`. Unify it with the input and check for
	// errors.
	//
	// This branch is why a typo'd operator used to pass silently: the input is
	// encoded from a map[string]any, so it is an OPEN struct, and unifying
	// `{mach: {...}}` (a misspelling of `match`) simply added a new field and
	// succeeded. Guard the branch before unifying — see exprConstrainsInput.
	if reason := exprConstrainsInput(expr, input); reason != "" {
		return false, bindings, reason
	}

	unified := input.Unify(expr)
	if unified.Err() != nil {
		return false, bindings, unified.Err().Error()
	}

	// Require the unified result to be concrete. Without this, a constraint
	// naming a field the input does not have (`expr: {spec: {required:
	// string}}`) stays non-concrete and passes vacuously.
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		return false, bindings, fmt.Sprintf("constraint not satisfied: %v", err)
	}

	return true, bindings, ""
}

// knownExprOperators is the closed set of structured expression operators,
// matching #Expression in schemas/policy.cue. Every entry has a dedicated
// branch in evaluateExpression above.
var knownExprOperators = map[string]bool{
	"forEach":  true,
	"all":      true,
	"any":      true,
	"not":      true,
	"exists":   true,
	"absent":   true,
	"contains": true,
	"match":    true,
	"compare":  true,
	"func":     true,
}

// exprConstrainsInput guards the raw-CUE-constraint fallback. It returns a
// failure reason when the expression looks like a misspelled operator rather
// than a constraint over the input.
//
// The discriminator: a genuine raw constraint narrows a field that EXISTS on
// the input, whereas a typo'd operator introduces a field that does not. We
// cannot simply reject unknown keys — raw constraints are a supported,
// tested feature (see TestEvaluate_RawConstraint_DirLoad_Concurrent).
func exprConstrainsInput(expr cue.Value, input cue.Value) string {
	iter, err := expr.Fields()
	if err != nil {
		// Not a struct: nothing to discriminate, let Unify decide.
		return ""
	}

	for iter.Next() {
		name := iter.Selector().Unquoted()
		if knownExprOperators[name] {
			// Handled by a branch above; reaching here means it coexists with
			// other fields, which is still fine to unify.
			continue
		}
		if input.LookupPath(cue.MakePath(cue.Str(name))).Exists() {
			continue
		}
		return fmt.Sprintf(
			"unknown expr operator %q, and the input has no field %q for it to constrain. "+
				"Valid operators are: absent, all, any, compare, contains, exists, forEach, func, match, not.",
			name, name)
	}

	return ""
}

// evaluateFunc evaluates a builtin function call expression.
func (e *Engine) evaluateFunc(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	// Get function name
	nameVal := expr.LookupPath(cue.ParsePath("name"))
	if !nameVal.Exists() {
		return false, bindings, "func requires 'name'"
	}
	name, _ := nameVal.String()

	// Look up the builtin
	fn, ok := e.builtins[name]
	if !ok {
		return false, bindings, fmt.Sprintf("unknown builtin function: %s", name)
	}

	// Resolve arguments
	argsVal := expr.LookupPath(cue.ParsePath("args"))
	var args []any
	if argsVal.Exists() {
		iter, _ := argsVal.List()
		for iter.Next() {
			arg := iter.Value()
			// If it's a string that looks like an input path reference (starts with "input.")
			if s, err := arg.String(); err == nil && strings.HasPrefix(s, "input.") {
				// Resolve from input
				path := strings.TrimPrefix(s, "input.")
				resolved := input.LookupPath(cue.ParsePath(path))
				if resolved.Exists() {
					var v any
					if err := resolved.Decode(&v); err == nil {
						args = append(args, v)
						continue
					}
				}
				// If resolution fails, use the string literal
				args = append(args, s)
			} else {
				// Decode the literal value
				var v any
				if err := arg.Decode(&v); err == nil {
					args = append(args, v)
				} else {
					args = append(args, nil)
				}
			}
		}
	}

	// Call the builtin
	result, err := fn(ctx, args...)
	if err != nil {
		return false, bindings, fmt.Sprintf("builtin %s failed: %v", name, err)
	}

	// Bind result if requested
	bindVal := expr.LookupPath(cue.ParsePath("bind"))
	if bindVal.Exists() {
		bindName, _ := bindVal.String()
		if bindName != "" {
			bindings[bindName] = result
		}
	}

	// Check expectation if present
	expectVal := expr.LookupPath(cue.ParsePath("expect"))
	if expectVal.Exists() {
		expected, err := decodeAny(expectVal)
		if err != nil {
			return false, bindings, fmt.Sprintf("builtin %s: cannot decode expect: %v", name, err)
		}

		// Compare result with expected value
		if valuesEqual(result, expected) {
			return true, bindings, ""
		}
		return false, bindings, fmt.Sprintf("builtin %s returned %v, expected %v", name, result, expected)
	}

	// No expectation: a truthy result passes. Zero, empty string, empty
	// collection and nil all fail.
	if ok, reason := builtinResultTruthy(result); !ok {
		return false, bindings, fmt.Sprintf("builtin %s %s", name, reason)
	}

	return true, bindings, ""
}

// evaluateMatch evaluates a match expression.
func (e *Engine) evaluateMatch(expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	pathVal := expr.LookupPath(cue.ParsePath("path"))
	if !pathVal.Exists() {
		return false, bindings, "match requires 'path'"
	}
	path, _ := pathVal.String()

	// Get value at path
	fieldVal := input.LookupPath(cue.ParsePath(path))

	// requireField wraps operators that need the path to resolve; 'exists' is
	// the only operator that inspects absence itself. The numeric comparisons
	// carry their own not-found handling inside numericComparison.
	requireField := func(eval func(op cue.Value) (bool, string)) func(cue.Value) (bool, string) {
		return func(op cue.Value) (bool, string) {
			if !fieldVal.Exists() {
				return false, fmt.Sprintf("path '%s' not found", path)
			}
			return eval(op)
		}
	}
	// delegate adapts the family evaluators (set, length, semver, datetime),
	// folding their bindings into this match's bindings.
	delegate := func(eval func(fieldVal, op cue.Value, path string) (bool, map[string]any, string)) func(cue.Value) (bool, string) {
		return requireField(func(op cue.Value) (bool, string) {
			ok, b, reason := eval(fieldVal, op, path)
			for k, v := range b {
				bindings[k] = v
			}
			return ok, reason
		})
	}
	numericOp := func(symbol string, cmp func(actual, expected float64) bool) func(cue.Value) (bool, string) {
		return func(op cue.Value) (bool, string) {
			return numericComparison(fieldVal, op, path, symbol, cmp)
		}
	}

	ops := []specOp{
		{"exists", func(op cue.Value) (bool, string) {
			shouldExist, _ := op.Bool()
			exists := fieldVal.Exists() && fieldVal.Kind() != cue.NullKind
			if shouldExist && !exists {
				return false, fmt.Sprintf("field '%s' does not exist", path)
			}
			if !shouldExist && exists {
				return false, fmt.Sprintf("field '%s' should not exist", path)
			}
			return true, ""
		}},
		{"pattern", requireField(func(op cue.Value) (bool, string) {
			fieldStr, err := fieldVal.String()
			if err != nil {
				return false, fmt.Sprintf("path '%s' is not a string", path)
			}
			pattern, _ := op.String()
			re, err := e.getCompiledRegex(pattern)
			if err != nil {
				return false, fmt.Sprintf("invalid pattern: %s", err)
			}
			if !re.MatchString(fieldStr) {
				return false, fmt.Sprintf("'%s' does not match pattern '%s'", fieldStr, pattern)
			}
			return true, ""
		})},
		{"equals", requireField(func(op cue.Value) (bool, string) {
			expected, err := decodeAny(op)
			if err != nil {
				return false, fmt.Sprintf("'equals' operand for '%s' is not decodable: %v", path, err)
			}
			actual, err := decodeAny(fieldVal)
			if err != nil {
				return false, fmt.Sprintf("'%s' is not decodable: %v", path, err)
			}
			if !valuesEqual(actual, expected) {
				return false, fmt.Sprintf("'%s' expected '%v', got '%v'", path, expected, actual)
			}
			return true, ""
		})},
		{"greaterThan", numericOp(">", func(a, e float64) bool { return a > e })},
		{"greaterThanOrEqual", numericOp(">=", func(a, e float64) bool { return a >= e })},
		{"lessThan", numericOp("<", func(a, e float64) bool { return a < e })},
		{"lessThanOrEqual", numericOp("<=", func(a, e float64) bool { return a <= e })},
		{"in", requireField(func(op cue.Value) (bool, string) {
			actual, err := decodeAny(fieldVal)
			if err != nil {
				return false, fmt.Sprintf("'%s' is not decodable: %v", path, err)
			}
			iter, err := op.List()
			if err != nil {
				return false, "'in' must be a list"
			}
			found := false
			var allowedValues []string
			for iter.Next() {
				v, err := decodeAny(iter.Value())
				if err != nil {
					return false, fmt.Sprintf("'in' list entry is not decodable: %v", err)
				}
				allowedValues = append(allowedValues, fmt.Sprintf("%v", v))
				if valuesEqual(actual, v) {
					found = true
					break
				}
			}
			if !found {
				return false, fmt.Sprintf("'%s' value '%v' not in allowed list %v", path, actual, allowedValues)
			}
			return true, ""
		})},
		{"notIn", requireField(func(op cue.Value) (bool, string) {
			actual, err := decodeAny(fieldVal)
			if err != nil {
				return false, fmt.Sprintf("'%s' is not decodable: %v", path, err)
			}
			iter, err := op.List()
			if err != nil {
				return false, "'notIn' must be a list"
			}
			for iter.Next() {
				v, err := decodeAny(iter.Value())
				if err != nil {
					return false, fmt.Sprintf("'notIn' list entry is not decodable: %v", err)
				}
				if valuesEqual(actual, v) {
					return false, fmt.Sprintf("'%s' value '%v' is in forbidden list", path, actual)
				}
			}
			return true, ""
		})},
		{"contains", requireField(func(op cue.Value) (bool, string) {
			fieldStr, err := fieldVal.String()
			if err != nil {
				return false, fmt.Sprintf("path '%s' is not a string", path)
			}
			substr, _ := op.String()
			if !strings.Contains(fieldStr, substr) {
				return false, fmt.Sprintf("'%s' does not contain '%s'", path, substr)
			}
			return true, ""
		})},
		{"hasPrefix", requireField(func(op cue.Value) (bool, string) {
			fieldStr, err := fieldVal.String()
			if err != nil {
				return false, fmt.Sprintf("path '%s' is not a string", path)
			}
			prefix, _ := op.String()
			if !strings.HasPrefix(fieldStr, prefix) {
				return false, fmt.Sprintf("'%s' does not have prefix '%s'", path, prefix)
			}
			return true, ""
		})},
		{"hasSuffix", requireField(func(op cue.Value) (bool, string) {
			fieldStr, err := fieldVal.String()
			if err != nil {
				return false, fmt.Sprintf("path '%s' is not a string", path)
			}
			suffix, _ := op.String()
			if !strings.HasSuffix(fieldStr, suffix) {
				return false, fmt.Sprintf("'%s' does not have suffix '%s'", path, suffix)
			}
			return true, ""
		})},
		{"unique", delegate(e.evaluateUnique)},
		{"uniqueBy", delegate(e.evaluateUniqueBy)},
		{"sorted", delegate(e.evaluateSorted)},
		{"containsAll", delegate(e.evaluateContainsAll)},
		{"subsetOf", delegate(e.evaluateSubsetOf)},
		{"length", delegate(e.evaluateLength)},
		{"semver", delegate(e.evaluateSemver)},
		{"datetime", delegate(e.evaluateDatetime)},
	}

	specified, ok, reason := evaluateAllSpecified(expr, ops)
	if specified == 0 {
		return false, bindings, "match requires one of: exists, pattern, equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, in, notIn, contains, hasPrefix, hasSuffix, unique, uniqueBy, sorted, containsAll, subsetOf, length, semver, datetime"
	}
	return ok, bindings, reason
}

// evaluateCompare evaluates a compare expression.
func (e *Engine) evaluateCompare(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	leftVal := expr.LookupPath(cue.ParsePath("left"))
	opVal := expr.LookupPath(cue.ParsePath("op"))
	rightVal := expr.LookupPath(cue.ParsePath("right"))

	if !leftVal.Exists() || !opVal.Exists() || !rightVal.Exists() {
		return false, bindings, "compare requires 'left', 'op', and 'right'"
	}

	left, err := e.resolveValue(ctx, leftVal, input)
	if err != nil {
		return false, bindings, fmt.Sprintf("compare 'left': %v", err)
	}
	op, _ := opVal.String()
	right, err := e.resolveValue(ctx, rightVal, input)
	if err != nil {
		return false, bindings, fmt.Sprintf("compare 'right': %v", err)
	}

	result, reason := e.compare(left, op, right)
	if !result {
		if reason == "" {
			reason = fmt.Sprintf("comparison failed: %v %s %v", left, op, right)
		}
		return false, bindings, reason
	}

	return true, bindings, ""
}

// resolveValue resolves a Value to an actual value. Failures are returned
// rather than collapsed to nil so the caller can fail closed with a reason,
// matching compare's behaviour on malformed operands.
//
// A path that does not exist in the input is not an error: it resolves to nil
// and the comparison reports it as a non-numeric/mismatched operand.
func (e *Engine) resolveValue(ctx context.Context, val cue.Value, input cue.Value) (any, error) {
	// Check for literal
	if litVal := val.LookupPath(cue.ParsePath("literal")); litVal.Exists() {
		v, err := decodeAny(litVal)
		if err != nil {
			return nil, fmt.Errorf("literal is not decodable: %w", err)
		}
		return v, nil
	}

	// Check for path reference
	if pathVal := val.LookupPath(cue.ParsePath("path")); pathVal.Exists() {
		path, err := pathVal.String()
		if err != nil {
			return nil, fmt.Errorf("path must be a string: %w", err)
		}
		fieldVal := input.LookupPath(cue.ParsePath(path))
		if !fieldVal.Exists() {
			return nil, nil
		}
		v, err := decodeAny(fieldVal)
		if err != nil {
			return nil, fmt.Errorf("path %q is not decodable: %w", path, err)
		}
		return v, nil
	}

	// Check for func call
	if funcVal := val.LookupPath(cue.ParsePath("func")); funcVal.Exists() {
		nameVal := funcVal.LookupPath(cue.ParsePath("name"))
		if !nameVal.Exists() {
			return nil, fmt.Errorf("func requires a 'name'")
		}
		name, err := nameVal.String()
		if err != nil {
			return nil, fmt.Errorf("func 'name' must be a string: %w", err)
		}
		fn, ok := e.builtins[name]
		if !ok {
			return nil, fmt.Errorf("unknown builtin %q", name)
		}

		// Resolve arguments
		argsVal := funcVal.LookupPath(cue.ParsePath("args"))
		var args []any
		if argsVal.Exists() {
			iter, err := argsVal.List()
			if err != nil {
				return nil, fmt.Errorf("func 'args' must be a list: %w", err)
			}
			for iter.Next() {
				resolved, err := e.resolveValue(ctx, iter.Value(), input)
				if err != nil {
					return nil, fmt.Errorf("func %q argument: %w", name, err)
				}
				args = append(args, resolved)
			}
		}

		// Pass the request context so a builtin honours the evaluation
		// deadline and client cancellation.
		result, err := fn(ctx, args...)
		if err != nil {
			return nil, fmt.Errorf("builtin %q: %w", name, err)
		}
		return result, nil
	}

	// Note: `{env: "NAME"}` is deliberately not supported. Policy authors are
	// not necessarily server operators, and violation messages interpolate
	// resolved values back to the caller, so reading the server's environment
	// would let any policy exfiltrate credentials over /v1/evaluate. Inject
	// the value into the evaluation input instead.
	if val.LookupPath(cue.ParsePath("env")).Exists() {
		return nil, fmt.Errorf("value source 'env' is not supported: reading server environment variables from a policy is disallowed; pass the value in the evaluation input instead")
	}

	return nil, fmt.Errorf("value must specify one of 'path', 'literal', or 'func'")
}

// compare performs a comparison operation. It returns whether the comparison
// passed and, when it did not, a diagnostic reason. Malformed operands
// (non-numeric values for numeric operators, unparseable semver/datetime
// strings, invalid regex patterns, unknown operators) fail closed with a
// reason instead of being silently coerced to zero values.
func (e *Engine) compare(left any, op string, right any) (bool, string) {
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	switch op {
	case "==", "eq":
		return valuesEqual(left, right), ""
	case "!=", "ne", "neq":
		return !valuesEqual(left, right), ""
	case ">", "gt", ">=", "gte", "<", "lt", "<=", "lte":
		lf, lok := toFloatOk(left)
		rf, rok := toFloatOk(right)
		if !lok {
			return false, fmt.Sprintf("non-numeric operand %v for %q", left, op)
		}
		if !rok {
			return false, fmt.Sprintf("non-numeric operand %v for %q", right, op)
		}
		switch op {
		case ">", "gt":
			return lf > rf, ""
		case ">=", "gte":
			return lf >= rf, ""
		case "<", "lt":
			return lf < rf, ""
		default: // "<=", "lte"
			return lf <= rf, ""
		}
	case "in":
		if arr, ok := right.([]any); ok {
			for _, v := range arr {
				if valuesEqual(left, v) {
					return true, ""
				}
			}
		}
		return false, ""
	case "not_in", "notIn":
		if arr, ok := right.([]any); ok {
			for _, v := range arr {
				if valuesEqual(left, v) {
					return false, ""
				}
			}
		}
		return true, ""
	case "contains":
		return strings.Contains(leftStr, rightStr), ""
	case "hasPrefix", "startsWith":
		return strings.HasPrefix(leftStr, rightStr), ""
	case "hasSuffix", "endsWith":
		return strings.HasSuffix(leftStr, rightStr), ""
	case "matches":
		re, err := e.getCompiledRegex(rightStr)
		if err != nil {
			return false, fmt.Sprintf("invalid pattern %q: %v", rightStr, err)
		}
		return re.MatchString(leftStr), ""
	// Semantic version comparisons
	case "semverGt", "semverGte", "semverLt", "semverLte", "semverEq":
		cmp, err := compareSemver(leftStr, rightStr)
		if err != nil {
			return false, fmt.Sprintf("invalid semver operand: %v", err)
		}
		switch op {
		case "semverGt":
			return cmp > 0, ""
		case "semverGte":
			return cmp >= 0, ""
		case "semverLt":
			return cmp < 0, ""
		case "semverLte":
			return cmp <= 0, ""
		default: // "semverEq"
			return cmp == 0, ""
		}
	// Datetime comparisons
	case "after", "before", "afterOrEqual", "beforeOrEqual":
		cmp, err := compareDatetime(leftStr, rightStr)
		if err != nil {
			return false, fmt.Sprintf("invalid datetime operand: %v", err)
		}
		switch op {
		case "after":
			return cmp > 0, ""
		case "before":
			return cmp < 0, ""
		case "afterOrEqual":
			return cmp >= 0, ""
		default: // "beforeOrEqual"
			return cmp <= 0, ""
		}
	}
	return false, fmt.Sprintf("unknown comparison operator %q", op)
}

// evaluateForEach evaluates a forEach expression against an array in input.
// forEach iterates over an array and applies a condition to each element.
// Syntax: forEach: { path: "spec.containers", as: "container", condition: { match: {...} } }
func (e *Engine) evaluateForEach(ctx context.Context, expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	pathVal := expr.LookupPath(cue.ParsePath("path"))
	if !pathVal.Exists() {
		return false, bindings, "forEach requires 'path'"
	}
	path, _ := pathVal.String()

	// Get the array at path
	arrayVal := input.LookupPath(cue.ParsePath(path))
	if !arrayVal.Exists() {
		return false, bindings, fmt.Sprintf("path '%s' not found", path)
	}

	// Check if it's a list
	iter, err := arrayVal.List()
	if err != nil {
		return false, bindings, fmt.Sprintf("path '%s' is not an array", path)
	}

	// Get the alias for the current element (default: "item")
	alias := "item"
	if asVal := expr.LookupPath(cue.ParsePath("as")); asVal.Exists() {
		alias, _ = asVal.String()
	}

	// Get the condition to apply to each element
	conditionVal := expr.LookupPath(cue.ParsePath("condition"))
	if !conditionVal.Exists() {
		return false, bindings, "forEach requires 'condition'"
	}

	// Check for mode: "all" (default) or "any"
	mode := "all"
	if modeVal := expr.LookupPath(cue.ParsePath("mode")); modeVal.Exists() {
		mode, _ = modeVal.String()
	}

	// Iterate over the array
	index := 0
	var failedItems []string
	anyPassed := false

	for iter.Next() {
		itemVal := iter.Value()

		// Create a new input context with the current item aliased
		// We need to merge the item into the input under the alias
		itemInput, err := e.createItemContext(ctx, input, itemVal, alias, index)
		if err != nil {
			// Fail closed: an element we could not bind is not an element we
			// verified.
			return false, bindings, fmt.Sprintf("forEach over '%s': %v", path, err)
		}

		passed, b, msg := e.evaluateExpression(ctx, conditionVal, itemInput)
		for k, v := range b {
			bindings[k] = v
		}

		if mode == "all" && !passed {
			failedItems = append(failedItems, fmt.Sprintf("%s[%d]: %s", path, index, msg))
		}

		if mode == "any" && passed {
			anyPassed = true
		}

		index++
	}

	// Empty array handling
	if index == 0 {
		// Check if empty arrays should pass or fail
		if allowEmptyVal := expr.LookupPath(cue.ParsePath("allowEmpty")); allowEmptyVal.Exists() {
			allowEmpty, _ := allowEmptyVal.Bool()
			if !allowEmpty {
				return false, bindings, fmt.Sprintf("path '%s' is an empty array", path)
			}
		}
		return true, bindings, ""
	}

	if mode == "all" {
		if len(failedItems) > 0 {
			return false, bindings, strings.Join(failedItems, "; ")
		}
		return true, bindings, ""
	}

	// mode == "any"
	if anyPassed {
		return true, bindings, ""
	}
	return false, bindings, fmt.Sprintf("no items in '%s' matched the condition", path)
}

// createItemContext returns the input value with the current forEach element
// bound under alias and its position under "_index".
//
// Fast path: the element is grafted onto the existing input via FillPath —
// no decode/re-encode of the whole input — so the per-element cost is
// independent of input size. FillPath unifies rather than replaces, so when
// the alias or "_index" already exists on the input (an unlucky field name,
// or a nested forEach re-binding), fall back to rebuilding the input map,
// which preserves the replace semantics.
func (e *Engine) createItemContext(ctx context.Context, input cue.Value, item cue.Value, alias string, index int) (cue.Value, error) {
	aliasPath := cue.MakePath(cue.Str(alias))
	indexPath := cue.MakePath(cue.Str("_index"))

	if !input.LookupPath(aliasPath).Exists() && !input.LookupPath(indexPath).Exists() {
		indexVal := e.getCueContext(ctx).Encode(index)
		return input.FillPath(aliasPath, item).FillPath(indexPath, indexVal), nil
	}

	// Fallback: rebuild via Go values so the new bindings replace the old.
	var inputMap map[string]any
	if err := input.Decode(&inputMap); err != nil {
		return cue.Value{}, fmt.Errorf("rebuilding element context: input is not decodable: %w", err)
	}
	if inputMap == nil {
		inputMap = make(map[string]any)
	}

	itemData, err := decodeAny(item)
	if err != nil {
		return cue.Value{}, fmt.Errorf("rebuilding element context: element %d is not decodable: %w", index, err)
	}

	inputMap[alias] = itemData
	inputMap["_index"] = index

	return e.getCueContext(ctx).Encode(inputMap), nil
}

// evaluateContainsExpr evaluates a standalone contains expression.
// Checks if a collection at the given path contains specific values.
//
//	contains: { path: "spec.tags", value: "production" }             // single value
//	contains: { path: "spec.tags", all: ["production", "reviewed"] } // all must be present
//	contains: { path: "spec.tags", any: ["staging", "production"] }  // at least one
func (e *Engine) evaluateContainsExpr(expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	pathVal := expr.LookupPath(cue.ParsePath("path"))
	if !pathVal.Exists() {
		return false, bindings, "contains requires 'path'"
	}
	path, _ := pathVal.String()

	fieldVal := input.LookupPath(cue.ParsePath(path))
	if !fieldVal.Exists() {
		return false, bindings, fmt.Sprintf("path '%s' not found", path)
	}

	// Decode the collection
	var collection []any
	if err := fieldVal.Decode(&collection); err != nil {
		// Try as string contains
		if s, sErr := fieldVal.String(); sErr == nil {
			// Single value check on string
			if checkVal := expr.LookupPath(cue.ParsePath("value")); checkVal.Exists() {
				needle, nErr := checkVal.String()
				if nErr != nil {
					return false, bindings, fmt.Sprintf("'contains.value' must be a string when '%s' is a string: %v", path, nErr)
				}
				if strings.Contains(s, needle) {
					return true, bindings, ""
				}
				return false, bindings, fmt.Sprintf("'%s' does not contain '%s'", path, needle)
			}
		}
		return false, bindings, fmt.Sprintf("path '%s' is not a collection", path)
	}

	// Single value check
	if checkVal := expr.LookupPath(cue.ParsePath("value")); checkVal.Exists() {
		needle, err := decodeAny(checkVal)
		if err != nil {
			return false, bindings, fmt.Sprintf("'contains.value' is not decodable: %v", err)
		}
		for _, item := range collection {
			if valuesEqual(item, needle) {
				return true, bindings, ""
			}
		}
		return false, bindings, fmt.Sprintf("'%s' does not contain %v", path, needle)
	}

	// All values must be present
	if allVal := expr.LookupPath(cue.ParsePath("all")); allVal.Exists() {
		var required []any
		if err := allVal.Decode(&required); err != nil {
			return false, bindings, fmt.Sprintf("'contains.all' must be a list: %v", err)
		}
		for _, needle := range required {
			found := false
			for _, item := range collection {
				if valuesEqual(item, needle) {
					found = true
					break
				}
			}
			if !found {
				return false, bindings, fmt.Sprintf("'%s' missing required value %v", path, needle)
			}
		}
		return true, bindings, ""
	}

	// Any value must be present
	if anyVal := expr.LookupPath(cue.ParsePath("any")); anyVal.Exists() {
		var candidates []any
		if err := anyVal.Decode(&candidates); err != nil {
			return false, bindings, fmt.Sprintf("'contains.any' must be a list: %v", err)
		}
		for _, needle := range candidates {
			for _, item := range collection {
				if valuesEqual(item, needle) {
					return true, bindings, ""
				}
			}
		}
		return false, bindings, fmt.Sprintf("'%s' contains none of the expected values", path)
	}

	return false, bindings, "contains requires 'value', 'all', or 'any'"
}

// evaluateLength evaluates length conditions on arrays or strings
func (e *Engine) evaluateLength(fieldVal cue.Value, lengthExpr cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	// Get the length of the field
	var length int
	switch fieldVal.Kind() {
	case cue.ListKind:
		iter, _ := fieldVal.List()
		for iter.Next() {
			length++
		}
	case cue.StringKind:
		s, _ := fieldVal.String()
		length = len(s)
	default:
		return false, bindings, fmt.Sprintf("'%s' is not an array or string", path)
	}

	bindings["length"] = length

	intOp := func(check func(expected int64) (bool, string)) func(cue.Value) (bool, string) {
		return func(op cue.Value) (bool, string) {
			expected, _ := op.Int64()
			return check(expected)
		}
	}

	ops := []specOp{
		{"equals", intOp(func(expected int64) (bool, string) {
			if int64(length) != expected {
				return false, fmt.Sprintf("'%s' length is %d, expected %d", path, length, expected)
			}
			return true, ""
		})},
		{"greaterThan", intOp(func(expected int64) (bool, string) {
			if int64(length) <= expected {
				return false, fmt.Sprintf("'%s' length is %d, expected > %d", path, length, expected)
			}
			return true, ""
		})},
		{"greaterThanOrEqual", intOp(func(expected int64) (bool, string) {
			if int64(length) < expected {
				return false, fmt.Sprintf("'%s' length is %d, expected >= %d", path, length, expected)
			}
			return true, ""
		})},
		{"lessThan", intOp(func(expected int64) (bool, string) {
			if int64(length) >= expected {
				return false, fmt.Sprintf("'%s' length is %d, expected < %d", path, length, expected)
			}
			return true, ""
		})},
		{"lessThanOrEqual", intOp(func(expected int64) (bool, string) {
			if int64(length) > expected {
				return false, fmt.Sprintf("'%s' length is %d, expected <= %d", path, length, expected)
			}
			return true, ""
		})},
		{"min", intOp(func(min int64) (bool, string) {
			if int64(length) < min {
				return false, fmt.Sprintf("'%s' length is %d, minimum is %d", path, length, min)
			}
			return true, ""
		})},
		{"max", intOp(func(max int64) (bool, string) {
			if int64(length) > max {
				return false, fmt.Sprintf("'%s' length is %d, maximum is %d", path, length, max)
			}
			return true, ""
		})},
	}

	specified, ok, reason := evaluateAllSpecified(lengthExpr, ops)
	if specified == 0 {
		return false, bindings, "length requires one of: equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, min, max"
	}
	return ok, bindings, reason
}
