package engine

import (
	"fmt"
	"strconv"
	"strings"

	"cuelang.org/go/cue"
)

// evaluateSemver evaluates semantic version comparisons
func (e *Engine) evaluateSemver(fieldVal cue.Value, semverExpr cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	version, err := fieldVal.String()
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a string", path)
	}

	// Parse the actual version
	actualVer, err := parseSemver(version)
	if err != nil {
		return false, bindings, fmt.Sprintf("'%s' is not a valid semver: %s", path, version)
	}
	bindings["version"] = version

	// cmpOp builds one comparison operator; pass decides whether the
	// compareSemverParsed result satisfies it.
	cmpOp := func(name, symbol string, pass func(cmp int) bool) specOp {
		return specOp{name, func(op cue.Value) (bool, string) {
			expected, _ := op.String()
			expectedVer, err := parseSemver(expected)
			if err != nil {
				return false, fmt.Sprintf("invalid expected semver: %s", expected)
			}
			if !pass(compareSemverParsed(actualVer, expectedVer)) {
				if symbol == "==" {
					return false, fmt.Sprintf("'%s' version %s != %s", path, version, expected)
				}
				return false, fmt.Sprintf("'%s' version %s is not %s %s", path, version, symbol, expected)
			}
			return true, ""
		}}
	}

	ops := []specOp{
		cmpOp("equals", "==", func(c int) bool { return c == 0 }),
		cmpOp("greaterThan", ">", func(c int) bool { return c > 0 }),
		cmpOp("greaterThanOrEqual", ">=", func(c int) bool { return c >= 0 }),
		cmpOp("lessThan", "<", func(c int) bool { return c < 0 }),
		cmpOp("lessThanOrEqual", "<=", func(c int) bool { return c <= 0 }),
		{"constraint", func(op cue.Value) (bool, string) {
			constraint, _ := op.String()
			matched, err := matchSemverConstraint(actualVer, constraint)
			if err != nil {
				return false, fmt.Sprintf("invalid semver constraint %q: %v", constraint, err)
			}
			if !matched {
				return false, fmt.Sprintf("'%s' version %s does not satisfy constraint %s", path, version, constraint)
			}
			return true, ""
		}},
	}

	specified, ok, reason := evaluateAllSpecified(semverExpr, ops)
	if specified == 0 {
		return false, bindings, "semver requires one of: equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, constraint"
	}
	return ok, bindings, reason
}

// semverParts holds parsed semantic version components
type semverParts struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
}

// parseSemver parses a semantic version string
func parseSemver(version string) (semverParts, error) {
	var parts semverParts

	// Remove leading 'v' if present
	version = strings.TrimPrefix(version, "v")

	// Split off build metadata
	if idx := strings.Index(version, "+"); idx >= 0 {
		parts.Build = version[idx+1:]
		version = version[:idx]
	}

	// Split off prerelease
	if idx := strings.Index(version, "-"); idx >= 0 {
		parts.Prerelease = version[idx+1:]
		version = version[:idx]
	}

	// Parse major.minor.patch. Reject malformed segments instead of
	// treating them as 0 — "garbage" must not compare equal to "0.0.0".
	segments := strings.Split(version, ".")
	if len(segments) > 3 {
		return parts, fmt.Errorf("invalid semver %q: too many version segments", version)
	}

	var err error
	if parts.Major, err = strconv.Atoi(segments[0]); err != nil {
		return parts, fmt.Errorf("invalid semver %q: bad major version", version)
	}
	if len(segments) >= 2 {
		if parts.Minor, err = strconv.Atoi(segments[1]); err != nil {
			return parts, fmt.Errorf("invalid semver %q: bad minor version", version)
		}
	}
	if len(segments) >= 3 {
		if parts.Patch, err = strconv.Atoi(segments[2]); err != nil {
			return parts, fmt.Errorf("invalid semver %q: bad patch version", version)
		}
	}

	return parts, nil
}

// compareSemverParsed compares two parsed semver versions
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func compareSemverParsed(a, b semverParts) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}

	// Prerelease comparison
	// A version with prerelease has lower precedence than one without
	if a.Prerelease == "" && b.Prerelease != "" {
		return 1
	}
	if a.Prerelease != "" && b.Prerelease == "" {
		return -1
	}
	if a.Prerelease != b.Prerelease {
		if a.Prerelease < b.Prerelease {
			return -1
		}
		return 1
	}

	return 0
}

// compareSemver compares two semver strings. It returns an error when either
// operand is not a valid semantic version.
func compareSemver(a, b string) (int, error) {
	aParts, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	bParts, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	return compareSemverParsed(aParts, bParts), nil
}

// matchSemverConstraint checks if a version matches a constraint like ">=1.0.0,<2.0.0".
// It returns an error when the constraint itself contains an invalid version.
func matchSemverConstraint(version semverParts, constraint string) (bool, error) {
	// Split constraint by comma for AND conditions
	conditions := strings.Split(constraint, ",")

	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}

		// Parse operator and version
		var op string
		var verStr string

		if strings.HasPrefix(cond, ">=") {
			op = ">="
			verStr = strings.TrimPrefix(cond, ">=")
		} else if strings.HasPrefix(cond, "<=") {
			op = "<="
			verStr = strings.TrimPrefix(cond, "<=")
		} else if strings.HasPrefix(cond, ">") {
			op = ">"
			verStr = strings.TrimPrefix(cond, ">")
		} else if strings.HasPrefix(cond, "<") {
			op = "<"
			verStr = strings.TrimPrefix(cond, "<")
		} else if strings.HasPrefix(cond, "=") {
			op = "="
			verStr = strings.TrimPrefix(cond, "=")
		} else if strings.HasPrefix(cond, "^") {
			// Caret: compatible with version (same major)
			op = "^"
			verStr = strings.TrimPrefix(cond, "^")
		} else if strings.HasPrefix(cond, "~") {
			// Tilde: patch-level changes allowed
			op = "~"
			verStr = strings.TrimPrefix(cond, "~")
		} else {
			// Assume exact match
			op = "="
			verStr = cond
		}

		constraintVer, err := parseSemver(strings.TrimSpace(verStr))
		if err != nil {
			return false, err
		}
		cmp := compareSemverParsed(version, constraintVer)

		switch op {
		case ">":
			if cmp <= 0 {
				return false, nil
			}
		case ">=":
			if cmp < 0 {
				return false, nil
			}
		case "<":
			if cmp >= 0 {
				return false, nil
			}
		case "<=":
			if cmp > 0 {
				return false, nil
			}
		case "=":
			if cmp != 0 {
				return false, nil
			}
		case "^":
			// Must be same major version and >= constraint
			if version.Major != constraintVer.Major || cmp < 0 {
				return false, nil
			}
		case "~":
			// Must be same major.minor and >= constraint
			if version.Major != constraintVer.Major || version.Minor != constraintVer.Minor || cmp < 0 {
				return false, nil
			}
		}
	}

	return true, nil
}
