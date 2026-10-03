package engine

import (
	"regexp"
	"strings"
	"time"
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

	// Numeric kinds: zero is falsey. "0" is a non-empty string and stays
	// truthy, handled by the case above.
	if f, ok := asNumber(v); ok {
		if f == 0 {
			return false, "returned 0"
		}
		return true, ""
	}

	return true, ""
}

// matchesPatternCached reports whether value matches a selector pattern,
// case-insensitively. "*" in a pattern matches any run of characters.
func (e *Engine) matchesPatternCached(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, value)
	}
	regexPattern := "^(?i:" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + ")$"
	re, err := sharedRegexCache.get(regexPattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// NestedString safely extracts a string field from nested maps. Exported so
// the server's audit logging resolves input fields with the same traversal
// the engine's target matching uses.
func NestedString(m map[string]any, keys ...string) string {
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
