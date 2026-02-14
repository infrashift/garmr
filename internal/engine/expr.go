package engine

import (
	"context"
	"fmt"
	"os"
	"regexp"
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
		return e.evaluateCompare(compareVal, input)
	}

	// Check for 'func' (builtin function call)
	if funcVal := expr.LookupPath(cue.ParsePath("func")); funcVal.Exists() {
		return e.evaluateFunc(ctx, funcVal, input)
	}

	// Check for 'ref' (reference to another policy's result)
	if refVal := expr.LookupPath(cue.ParsePath("ref")); refVal.Exists() {
		// ref is a forward-looking feature; currently passes (no-op)
		// Future: look up referenced policy/rule result
		return true, bindings, ""
	}

	// Default: try to unify and check for errors
	unified := input.Unify(expr)
	if unified.Err() != nil {
		return false, bindings, unified.Err().Error()
	}

	return true, bindings, ""
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
		var expected any
		expectVal.Decode(&expected)

		// Compare result with expected value
		if valuesEqual(result, expected) {
			return true, bindings, ""
		}
		return false, bindings, fmt.Sprintf("builtin %s returned %v, expected %v", name, result, expected)
	}

	// If no expectation, treat truthy result as pass
	// boolean true, non-zero number, non-empty string = pass
	switch v := result.(type) {
	case bool:
		if !v {
			return false, bindings, fmt.Sprintf("builtin %s returned false", name)
		}
	case nil:
		return false, bindings, fmt.Sprintf("builtin %s returned nil", name)
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

	// Check for 'exists' condition
	if existsVal := expr.LookupPath(cue.ParsePath("exists")); existsVal.Exists() {
		shouldExist, _ := existsVal.Bool()
		exists := fieldVal.Exists() && fieldVal.Kind() != cue.NullKind
		if shouldExist && !exists {
			return false, bindings, fmt.Sprintf("field '%s' does not exist", path)
		}
		if !shouldExist && exists {
			return false, bindings, fmt.Sprintf("field '%s' should not exist", path)
		}
		return true, bindings, ""
	}

	// Check for 'pattern' (regex match)
	if patternVal := expr.LookupPath(cue.ParsePath("pattern")); patternVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		pattern, _ := patternVal.String()
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid pattern: %s", err)
		}

		if !re.MatchString(fieldStr) {
			return false, bindings, fmt.Sprintf("'%s' does not match pattern '%s'", fieldStr, pattern)
		}
		return true, bindings, ""
	}

	// Check for 'equals' (exact match)
	if equalsVal := expr.LookupPath(cue.ParsePath("equals")); equalsVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual interface{}
		equalsVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if !valuesEqual(actual, expected) {
			return false, bindings, fmt.Sprintf("'%s' expected '%v', got '%v'", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'greaterThan'
	if gtVal := expr.LookupPath(cue.ParsePath("greaterThan")); gtVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		gtVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual <= expected {
			return false, bindings, fmt.Sprintf("'%s' expected > %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'greaterThanOrEqual'
	if gteVal := expr.LookupPath(cue.ParsePath("greaterThanOrEqual")); gteVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		gteVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual < expected {
			return false, bindings, fmt.Sprintf("'%s' expected >= %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'lessThan'
	if ltVal := expr.LookupPath(cue.ParsePath("lessThan")); ltVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		ltVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual >= expected {
			return false, bindings, fmt.Sprintf("'%s' expected < %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'lessThanOrEqual'
	if lteVal := expr.LookupPath(cue.ParsePath("lessThanOrEqual")); lteVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var expected, actual float64
		lteVal.Decode(&expected)
		fieldVal.Decode(&actual)

		if actual > expected {
			return false, bindings, fmt.Sprintf("'%s' expected <= %v, got %v", path, expected, actual)
		}
		return true, bindings, ""
	}

	// Check for 'in' (value in list)
	if inVal := expr.LookupPath(cue.ParsePath("in")); inVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var actual interface{}
		fieldVal.Decode(&actual)

		iter, err := inVal.List()
		if err != nil {
			return false, bindings, "'in' must be a list"
		}

		found := false
		var allowedValues []string
		for iter.Next() {
			var v interface{}
			iter.Value().Decode(&v)
			allowedValues = append(allowedValues, fmt.Sprintf("%v", v))
			if valuesEqual(actual, v) {
				found = true
				break
			}
		}

		if !found {
			return false, bindings, fmt.Sprintf("'%s' value '%v' not in allowed list %v", path, actual, allowedValues)
		}
		return true, bindings, ""
	}

	// Check for 'notIn' (value not in list)
	if notInVal := expr.LookupPath(cue.ParsePath("notIn")); notInVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		var actual interface{}
		fieldVal.Decode(&actual)

		iter, err := notInVal.List()
		if err != nil {
			return false, bindings, "'notIn' must be a list"
		}

		for iter.Next() {
			var v interface{}
			iter.Value().Decode(&v)
			if valuesEqual(actual, v) {
				return false, bindings, fmt.Sprintf("'%s' value '%v' is in forbidden list", path, actual)
			}
		}
		return true, bindings, ""
	}

	// Check for 'contains' (string contains)
	if containsVal := expr.LookupPath(cue.ParsePath("contains")); containsVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		substr, _ := containsVal.String()
		if !strings.Contains(fieldStr, substr) {
			return false, bindings, fmt.Sprintf("'%s' does not contain '%s'", path, substr)
		}
		return true, bindings, ""
	}

	// Check for 'hasPrefix'
	if prefixVal := expr.LookupPath(cue.ParsePath("hasPrefix")); prefixVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		prefix, _ := prefixVal.String()
		if !strings.HasPrefix(fieldStr, prefix) {
			return false, bindings, fmt.Sprintf("'%s' does not have prefix '%s'", path, prefix)
		}
		return true, bindings, ""
	}

	// Check for 'hasSuffix'
	if suffixVal := expr.LookupPath(cue.ParsePath("hasSuffix")); suffixVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}

		fieldStr, err := fieldVal.String()
		if err != nil {
			return false, bindings, fmt.Sprintf("path '%s' is not a string", path)
		}

		suffix, _ := suffixVal.String()
		if !strings.HasSuffix(fieldStr, suffix) {
			return false, bindings, fmt.Sprintf("'%s' does not have suffix '%s'", path, suffix)
		}
		return true, bindings, ""
	}

	// Check for 'length' conditions (array or string length)
	if lengthVal := expr.LookupPath(cue.ParsePath("length")); lengthVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}
		return e.evaluateLength(fieldVal, lengthVal, path)
	}

	// Check for 'semver' (semantic version comparison)
	if semverVal := expr.LookupPath(cue.ParsePath("semver")); semverVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}
		return e.evaluateSemver(fieldVal, semverVal, path)
	}

	// Check for 'datetime' (date/time comparison)
	if datetimeVal := expr.LookupPath(cue.ParsePath("datetime")); datetimeVal.Exists() {
		if !fieldVal.Exists() {
			return false, bindings, fmt.Sprintf("path '%s' not found", path)
		}
		return e.evaluateDatetime(fieldVal, datetimeVal, path)
	}

	return false, bindings, "match requires one of: exists, pattern, equals, greaterThan, lessThan, in, notIn, contains, hasPrefix, hasSuffix, length, semver, datetime"
}

// evaluateCompare evaluates a compare expression.
func (e *Engine) evaluateCompare(expr cue.Value, input cue.Value) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	leftVal := expr.LookupPath(cue.ParsePath("left"))
	opVal := expr.LookupPath(cue.ParsePath("op"))
	rightVal := expr.LookupPath(cue.ParsePath("right"))

	if !leftVal.Exists() || !opVal.Exists() || !rightVal.Exists() {
		return false, bindings, "compare requires 'left', 'op', and 'right'"
	}

	left := e.resolveValue(leftVal, input)
	op, _ := opVal.String()
	right := e.resolveValue(rightVal, input)

	result := e.compare(left, op, right)
	if !result {
		return false, bindings, fmt.Sprintf("comparison failed: %v %s %v", left, op, right)
	}

	return true, bindings, ""
}

// resolveValue resolves a Value to an actual value.
func (e *Engine) resolveValue(val cue.Value, input cue.Value) any {
	// Check for literal
	if litVal := val.LookupPath(cue.ParsePath("literal")); litVal.Exists() {
		var v any
		litVal.Decode(&v)
		return v
	}

	// Check for path reference
	if pathVal := val.LookupPath(cue.ParsePath("path")); pathVal.Exists() {
		path, _ := pathVal.String()
		fieldVal := input.LookupPath(cue.ParsePath(path))
		if fieldVal.Exists() {
			var v any
			fieldVal.Decode(&v)
			return v
		}
		return nil
	}

	// Check for func call
	if funcVal := val.LookupPath(cue.ParsePath("func")); funcVal.Exists() {
		nameVal := funcVal.LookupPath(cue.ParsePath("name"))
		if !nameVal.Exists() {
			return nil
		}
		name, _ := nameVal.String()
		fn, ok := e.builtins[name]
		if !ok {
			return nil
		}

		// Resolve arguments
		argsVal := funcVal.LookupPath(cue.ParsePath("args"))
		var args []any
		if argsVal.Exists() {
			iter, _ := argsVal.List()
			for iter.Next() {
				resolved := e.resolveValue(iter.Value(), input)
				args = append(args, resolved)
			}
		}

		result, err := fn(context.Background(), args...)
		if err != nil {
			return nil
		}
		return result
	}

	// Check for env variable
	if envVal := val.LookupPath(cue.ParsePath("env")); envVal.Exists() {
		envName, _ := envVal.String()
		return os.Getenv(envName)
	}

	return nil
}

// compare performs comparison operation.
func (e *Engine) compare(left any, op string, right any) bool {
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	switch op {
	case "==", "eq":
		return valuesEqual(left, right)
	case "!=", "ne", "neq":
		return !valuesEqual(left, right)
	case ">", "gt":
		return toFloat(left) > toFloat(right)
	case ">=", "gte":
		return toFloat(left) >= toFloat(right)
	case "<", "lt":
		return toFloat(left) < toFloat(right)
	case "<=", "lte":
		return toFloat(left) <= toFloat(right)
	case "in":
		if arr, ok := right.([]any); ok {
			for _, v := range arr {
				if valuesEqual(left, v) {
					return true
				}
			}
		}
		return false
	case "not_in", "notIn":
		if arr, ok := right.([]any); ok {
			for _, v := range arr {
				if valuesEqual(left, v) {
					return false
				}
			}
		}
		return true
	case "contains":
		return strings.Contains(leftStr, rightStr)
	case "hasPrefix", "startsWith":
		return strings.HasPrefix(leftStr, rightStr)
	case "hasSuffix", "endsWith":
		return strings.HasSuffix(leftStr, rightStr)
	case "matches":
		re, err := regexp.Compile(rightStr)
		if err != nil {
			return false
		}
		return re.MatchString(leftStr)
	// Semantic version comparisons
	case "semverGt":
		return compareSemver(leftStr, rightStr) > 0
	case "semverGte":
		return compareSemver(leftStr, rightStr) >= 0
	case "semverLt":
		return compareSemver(leftStr, rightStr) < 0
	case "semverLte":
		return compareSemver(leftStr, rightStr) <= 0
	case "semverEq":
		return compareSemver(leftStr, rightStr) == 0
	// Datetime comparisons
	case "after":
		return compareDatetime(leftStr, rightStr) > 0
	case "before":
		return compareDatetime(leftStr, rightStr) < 0
	case "afterOrEqual":
		return compareDatetime(leftStr, rightStr) >= 0
	case "beforeOrEqual":
		return compareDatetime(leftStr, rightStr) <= 0
	}
	return false
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
		itemInput := e.createItemContext(ctx, input, itemVal, alias, index)

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

// createItemContext creates a new CUE value context with the item aliased.
// Uses the pooled CUE context from the Go context for thread safety.
func (e *Engine) createItemContext(ctx context.Context, input cue.Value, item cue.Value, alias string, index int) cue.Value {
	// Decode original input
	var inputMap map[string]any
	input.Decode(&inputMap)
	if inputMap == nil {
		inputMap = make(map[string]any)
	}

	// Decode item
	var itemData any
	item.Decode(&itemData)

	// Add item under alias
	inputMap[alias] = itemData
	inputMap["_index"] = index

	// Rebuild CUE value using pooled context
	return e.getCueContext(ctx).Encode(inputMap)
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
				var needle string
				checkVal.Decode(&needle)
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
		var needle any
		checkVal.Decode(&needle)
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
		allVal.Decode(&required)
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
		anyVal.Decode(&candidates)
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

	// Check various length conditions
	if eqVal := lengthExpr.LookupPath(cue.ParsePath("equals")); eqVal.Exists() {
		expected, _ := eqVal.Int64()
		if int64(length) != expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if gtVal := lengthExpr.LookupPath(cue.ParsePath("greaterThan")); gtVal.Exists() {
		expected, _ := gtVal.Int64()
		if int64(length) <= expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected > %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if gteVal := lengthExpr.LookupPath(cue.ParsePath("greaterThanOrEqual")); gteVal.Exists() {
		expected, _ := gteVal.Int64()
		if int64(length) < expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected >= %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if ltVal := lengthExpr.LookupPath(cue.ParsePath("lessThan")); ltVal.Exists() {
		expected, _ := ltVal.Int64()
		if int64(length) >= expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected < %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if lteVal := lengthExpr.LookupPath(cue.ParsePath("lessThanOrEqual")); lteVal.Exists() {
		expected, _ := lteVal.Int64()
		if int64(length) > expected {
			return false, bindings, fmt.Sprintf("'%s' length is %d, expected <= %d", path, length, expected)
		}
		return true, bindings, ""
	}

	if minVal := lengthExpr.LookupPath(cue.ParsePath("min")); minVal.Exists() {
		min, _ := minVal.Int64()
		if int64(length) < min {
			return false, bindings, fmt.Sprintf("'%s' length is %d, minimum is %d", path, length, min)
		}
		// Check max too if provided
		if maxVal := lengthExpr.LookupPath(cue.ParsePath("max")); maxVal.Exists() {
			max, _ := maxVal.Int64()
			if int64(length) > max {
				return false, bindings, fmt.Sprintf("'%s' length is %d, maximum is %d", path, length, max)
			}
		}
		return true, bindings, ""
	}

	if maxVal := lengthExpr.LookupPath(cue.ParsePath("max")); maxVal.Exists() {
		max, _ := maxVal.Int64()
		if int64(length) > max {
			return false, bindings, fmt.Sprintf("'%s' length is %d, maximum is %d", path, length, max)
		}
		return true, bindings, ""
	}

	return false, bindings, "length requires one of: equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, min, max"
}
