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

	// Check for 'after'
	if afterVal := datetimeExpr.LookupPath(cue.ParsePath("after")); afterVal.Exists() {
		expected, _ := afterVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if !actualTime.After(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is not after %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'before'
	if beforeVal := datetimeExpr.LookupPath(cue.ParsePath("before")); beforeVal.Exists() {
		expected, _ := beforeVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if !actualTime.Before(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is not before %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'afterOrEqual'
	if afterEqVal := datetimeExpr.LookupPath(cue.ParsePath("afterOrEqual")); afterEqVal.Exists() {
		expected, _ := afterEqVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if actualTime.Before(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is before %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'beforeOrEqual'
	if beforeEqVal := datetimeExpr.LookupPath(cue.ParsePath("beforeOrEqual")); beforeEqVal.Exists() {
		expected, _ := beforeEqVal.String()
		expectedTime, err := parseDateTime(expected)
		if err != nil {
			return false, bindings, fmt.Sprintf("invalid expected datetime: %s", expected)
		}
		if actualTime.After(expectedTime) {
			return false, bindings, fmt.Sprintf("'%s' %s is after %s", path, dateStr, expected)
		}
		return true, bindings, ""
	}

	// Check for 'withinDays' (relative to now)
	if withinDaysVal := datetimeExpr.LookupPath(cue.ParsePath("withinDays")); withinDaysVal.Exists() {
		days, _ := withinDaysVal.Int64()
		deadline := time.Now().AddDate(0, 0, int(days))
		if actualTime.After(deadline) {
			return false, bindings, fmt.Sprintf("'%s' %s is more than %d days from now", path, dateStr, days)
		}
		return true, bindings, ""
	}

	// Check for 'withinHours' (relative to now)
	if withinHoursVal := datetimeExpr.LookupPath(cue.ParsePath("withinHours")); withinHoursVal.Exists() {
		hours, _ := withinHoursVal.Int64()
		deadline := time.Now().Add(time.Duration(hours) * time.Hour)
		if actualTime.After(deadline) {
			return false, bindings, fmt.Sprintf("'%s' %s is more than %d hours from now", path, dateStr, hours)
		}
		return true, bindings, ""
	}

	// Check for 'expiresAfterDays' (must be at least N days in the future)
	if expiresAfterVal := datetimeExpr.LookupPath(cue.ParsePath("expiresAfterDays")); expiresAfterVal.Exists() {
		days, _ := expiresAfterVal.Int64()
		minExpiry := time.Now().AddDate(0, 0, int(days))
		if actualTime.Before(minExpiry) {
			return false, bindings, fmt.Sprintf("'%s' %s expires in less than %d days", path, dateStr, days)
		}
		return true, bindings, ""
	}

	// Check for 'notExpired' (must be in the future)
	if notExpiredVal := datetimeExpr.LookupPath(cue.ParsePath("notExpired")); notExpiredVal.Exists() {
		shouldNotBeExpired, _ := notExpiredVal.Bool()
		isExpired := actualTime.Before(time.Now())
		if shouldNotBeExpired && isExpired {
			return false, bindings, fmt.Sprintf("'%s' %s has expired", path, dateStr)
		}
		if !shouldNotBeExpired && !isExpired {
			return false, bindings, fmt.Sprintf("'%s' %s has not expired", path, dateStr)
		}
		return true, bindings, ""
	}

	return false, bindings, "datetime requires one of: after, before, afterOrEqual, beforeOrEqual, withinDays, withinHours, expiresAfterDays, notExpired"
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

// compareDatetime compares two datetime strings
func compareDatetime(a, b string) int {
	aTime, err := parseDateTime(a)
	if err != nil {
		return 0
	}
	bTime, err := parseDateTime(b)
	if err != nil {
		return 0
	}

	if aTime.Before(bTime) {
		return -1
	}
	if aTime.After(bTime) {
		return 1
	}
	return 0
}
