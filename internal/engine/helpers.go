package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

// getCompiledRegex returns a compiled regex from the cache, compiling and caching it if needed.
func (e *Engine) getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := e.regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	e.regexCache.Store(pattern, re)
	return re, nil
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
