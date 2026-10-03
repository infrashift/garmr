package engine

import (
	"fmt"
	"strings"
	"time"
)

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
