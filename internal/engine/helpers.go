package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cuelang.org/go/cue"
)

// stringInSlice checks if a string is in a slice.
func stringInSlice(s string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// anyTagMatches checks if any of the rule's tags match any of the filter tags.
func anyTagMatches(ruleTags, filterTags []string) bool {
	for _, rt := range ruleTags {
		for _, ft := range filterTags {
			if strings.EqualFold(rt, ft) {
				return true
			}
		}
	}
	return false
}

// valuesEqual performs type-aware comparison of two values, handling numeric type coercion.
func valuesEqual(a, b any) bool {
	// Try numeric comparison first
	aFloat, aIsNum := toFloatOk(a)
	bFloat, bIsNum := toFloatOk(b)
	if aIsNum && bIsNum {
		return aFloat == bFloat
	}

	// Fall back to string comparison
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// toFloatOk attempts to convert a value to float64, returning whether the conversion succeeded.
func toFloatOk(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	case int16:
		return float64(val), true
	case int8:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint64:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint16:
		return float64(val), true
	case uint8:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// builtinResultTruthy reports whether a builtin's return value counts as a
// pass when the rule declares no `expect:`. It returns a reason when the
// result is falsey.
//
// The previous implementation only handled bool and nil, so every other type
// fell through to "pass" — `func: {name: "len", args: [...]}` returning 0
// passed, making the assertion a silent no-op.
func builtinResultTruthy(v any) (bool, string) {
	switch val := v.(type) {
	case nil:
		return false, "returned nil"
	case bool:
		if !val {
			return false, "returned false"
		}
		return true, ""
	case string:
		if val == "" {
			return false, "returned an empty string"
		}
		return true, ""
	case time.Time:
		if val.IsZero() {
			return false, "returned the zero time"
		}
		return true, ""
	case []any:
		if len(val) == 0 {
			return false, "returned an empty list"
		}
		return true, ""
	case map[string]any:
		if len(val) == 0 {
			return false, "returned an empty struct"
		}
		return true, ""
	}

	// Numeric kinds: zero is falsey. Note this deliberately does not route
	// strings through toFloatOk — "0" is a non-empty string and stays truthy,
	// handled by the case above.
	if f, ok := toFloatOk(v); ok {
		if f == 0 {
			return false, "returned 0"
		}
		return true, ""
	}

	return true, ""
}

// decodeAny decodes a CUE value into a Go value, annotating failures with the
// value's path so the rule message can name the offending operand.
func decodeAny(v cue.Value) (any, error) {
	var out any
	if err := v.Decode(&out); err != nil {
		return nil, fmt.Errorf("%s: %w", v.Path(), err)
	}
	return out, nil
}

// numericOperand decodes a CUE value expected to be a number. It returns a
// human-readable reason instead of an error because every caller folds the
// reason straight into the rule's failure message.
//
// This exists so numeric comparisons fail closed with an explanation, matching
// `compare`. Previously the decode error was discarded, so comparing a string
// field with greaterThan silently produced 0 <= 0.
func numericOperand(v cue.Value, label string) (float64, string) {
	var f float64
	if err := v.Decode(&f); err != nil {
		concrete := "value"
		if s, serr := v.String(); serr == nil {
			concrete = strconv.Quote(s)
		} else if k := v.Kind(); k != cue.BottomKind {
			concrete = k.String()
		}
		return 0, fmt.Sprintf("%s is not numeric (got %s)", label, concrete)
	}
	return f, ""
}

// numericComparison decodes both operands of a numeric match operator and
// applies cmp. It exists so the four comparison operators share one
// malformed-operand path instead of four copies that silently coerced to zero.
func numericComparison(fieldVal, operandVal cue.Value, path, symbol string, cmp func(actual, expected float64) bool) (bool, string) {
	if !fieldVal.Exists() {
		return false, fmt.Sprintf("path '%s' not found", path)
	}

	expected, reason := numericOperand(operandVal, fmt.Sprintf("operand of '%s'", symbol))
	if reason != "" {
		return false, reason
	}
	actual, reason := numericOperand(fieldVal, fmt.Sprintf("'%s'", path))
	if reason != "" {
		return false, reason
	}

	if !cmp(actual, expected) {
		return false, fmt.Sprintf("'%s' expected %s %v, got %v", path, symbol, expected, actual)
	}
	return true, ""
}

// specOp is one operator of a condition-operator family (match, length,
// semver, datetime). eval receives the operand value and returns whether the
// operator passed and, on failure, the reason.
type specOp struct {
	name string
	eval func(op cue.Value) (bool, string)
}

// evaluateAllSpecified evaluates every operator present on expr and ANDs the
// results, so a block like `datetime: {after: X, before: Y}` enforces all of
// its operators instead of silently checking only the first. Reasons from
// every failing operator are joined so the violation names each unmet check.
func evaluateAllSpecified(expr cue.Value, ops []specOp) (specified int, ok bool, reason string) {
	var failures []string
	for _, o := range ops {
		op := expr.LookupPath(cue.ParsePath(o.name))
		if !op.Exists() {
			continue
		}
		specified++
		if passed, why := o.eval(op); !passed {
			failures = append(failures, why)
		}
	}
	return specified, len(failures) == 0, strings.Join(failures, "; ")
}

// getCompiledRegex returns a compiled regex from the engine's bounded cache,
// compiling and caching it if needed.
func (e *Engine) getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	return e.regexCache.get(pattern)
}

// matchesPatternCached checks if a value matches a pattern (supports * wildcard)
// using the engine's regex cache.
func (e *Engine) matchesPatternCached(pattern, value string) bool {
	// Case-insensitive comparison
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Exact match
	if pattern == value {
		return true
	}

	// Wildcard matching
	if strings.Contains(pattern, "*") {
		// Convert glob pattern to regex
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
		re, err := e.getCompiledRegex(regexPattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}

	return false
}

// getStringField safely extracts a string field from nested maps.
func getStringField(m map[string]any, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - get the value
			if val, ok := current[key]; ok {
				if s, ok := val.(string); ok {
					return s
				}
			}
			return ""
		}
		// Navigate deeper
		if next, ok := current[key]; ok {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return ""
			}
		} else {
			return ""
		}
	}
	return ""
}

// getMapField safely extracts a map field from nested maps.
func getMapField(m map[string]any, keys ...string) map[string]string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key - get the map
			if val, ok := current[key]; ok {
				if mapVal, ok := val.(map[string]any); ok {
					result := make(map[string]string)
					for k, v := range mapVal {
						if s, ok := v.(string); ok {
							result[k] = s
						}
					}
					return result
				}
			}
			return nil
		}
		// Navigate deeper
		if next, ok := current[key]; ok {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return nil
			}
		} else {
			return nil
		}
	}
	return nil
}
