package engine

import (
	"fmt"
	"strings"
	"time"

	"cuelang.org/go/cue"
)

// evaluateDatetime evaluates date/time comparisons
func (e *Engine) evaluateDatetime(fieldVal cue.Value, datetimeExpr cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	dateStr, err := fieldVal.String()
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a string", path)
	}

	// Parse the actual datetime
	actualTime, err := parseDateTime(dateStr)
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a valid datetime: %s", path, dateStr)
	}
	bindings["datetime"] = actualTime.Format(time.RFC3339)

	// timeOp builds one absolute-time comparison operator; pass decides
	// whether actualTime satisfies it relative to the operand, and failMsg
	// renders the violation for the operand's raw string.
	timeOp := func(name string, pass func(actual, expected time.Time) bool, failMsg func(expected string) string) specOp {
		return specOp{name, func(op cue.Value) (bool, string) {
			expected, _ := op.String()
			expectedTime, err := parseDateTime(expected)
			if err != nil {
				return false, fmt.Sprintf("invalid expected datetime: %s", expected)
			}
			if !pass(actualTime, expectedTime) {
				return false, failMsg(expected)
			}
			return true, ""
		}}
	}

	ops := []specOp{
		timeOp("after",
			func(a, e time.Time) bool { return a.After(e) },
			func(expected string) string {
				return fmt.Sprintf("'%s' %s is not after %s", path, dateStr, expected)
			}),
		timeOp("before",
			func(a, e time.Time) bool { return a.Before(e) },
			func(expected string) string {
				return fmt.Sprintf("'%s' %s is not before %s", path, dateStr, expected)
			}),
		timeOp("afterOrEqual",
			func(a, e time.Time) bool { return !a.Before(e) },
			func(expected string) string {
				return fmt.Sprintf("'%s' %s is before %s", path, dateStr, expected)
			}),
		timeOp("beforeOrEqual",
			func(a, e time.Time) bool { return !a.After(e) },
			func(expected string) string {
				return fmt.Sprintf("'%s' %s is after %s", path, dateStr, expected)
			}),
		{"withinDays", func(op cue.Value) (bool, string) {
			days, _ := op.Int64()
			deadline := time.Now().AddDate(0, 0, int(days))
			if actualTime.After(deadline) {
				return false, fmt.Sprintf("'%s' %s is more than %d days from now", path, dateStr, days)
			}
			return true, ""
		}},
		{"withinHours", func(op cue.Value) (bool, string) {
			hours, _ := op.Int64()
			deadline := time.Now().Add(time.Duration(hours) * time.Hour)
			if actualTime.After(deadline) {
				return false, fmt.Sprintf("'%s' %s is more than %d hours from now", path, dateStr, hours)
			}
			return true, ""
		}},
		{"expiresAfterDays", func(op cue.Value) (bool, string) {
			days, _ := op.Int64()
			minExpiry := time.Now().AddDate(0, 0, int(days))
			if actualTime.Before(minExpiry) {
				return false, fmt.Sprintf("'%s' %s expires in less than %d days", path, dateStr, days)
			}
			return true, ""
		}},
		{"notExpired", func(op cue.Value) (bool, string) {
			shouldNotBeExpired, _ := op.Bool()
			isExpired := actualTime.Before(time.Now())
			if shouldNotBeExpired && isExpired {
				return false, fmt.Sprintf("'%s' %s has expired", path, dateStr)
			}
			if !shouldNotBeExpired && !isExpired {
				return false, fmt.Sprintf("'%s' %s has not expired", path, dateStr)
			}
			return true, ""
		}},
	}

	specified, ok, reason := evaluateAllSpecified(datetimeExpr, ops)
	if specified == 0 {
		return false, bindings, "datetime requires one of: after, before, afterOrEqual, beforeOrEqual, withinDays, withinHours, expiresAfterDays, notExpired"
	}
	return ok, bindings, reason
}

// parseDateTime parses a datetime string in various formats
func parseDateTime(s string) (time.Time, error) {
	// Handle special value "now"
	if strings.ToLower(s) == "now" {
		return time.Now(), nil
	}

	// Try various formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006",
		"02-Jan-2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse datetime: %s", s)
}

// compareDatetime compares two datetime strings. It returns an error when
// either operand cannot be parsed — silently treating garbage as "equal"
// would make ordering operators fail open.
func compareDatetime(a, b string) (int, error) {
	aTime, err := parseDateTime(a)
	if err != nil {
		return 0, err
	}
	bTime, err := parseDateTime(b)
	if err != nil {
		return 0, err
	}

	if aTime.Before(bTime) {
		return -1, nil
	}
	if aTime.After(bTime) {
		return 1, nil
	}
	return 0, nil
}
