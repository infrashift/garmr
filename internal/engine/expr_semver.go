package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// semverParts holds parsed semantic version components.
type semverParts struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
	raw        string
}

// parseSemver parses a semantic version string. A leading "v" is accepted,
// and minor/patch may be omitted ("1.2" is 1.2.0).
func parseSemver(version string) (semverParts, error) {
	parts := semverParts{raw: version}

	version = strings.TrimPrefix(version, "v")

	if idx := strings.Index(version, "+"); idx >= 0 {
		parts.Build = version[idx+1:]
		version = version[:idx]
	}
	if idx := strings.Index(version, "-"); idx >= 0 {
		parts.Prerelease = version[idx+1:]
		version = version[:idx]
	}

	// Reject malformed segments instead of treating them as 0 — "garbage"
	// must not compare equal to "0.0.0".
	segments := strings.Split(version, ".")
	if len(segments) > 3 {
		return parts, fmt.Errorf("invalid semver %q: too many version segments", version)
	}
	nums := []*int{&parts.Major, &parts.Minor, &parts.Patch}
	for i, seg := range segments {
		n, err := strconv.Atoi(seg)
		if err != nil || n < 0 || strings.HasPrefix(seg, "+") {
			return parts, fmt.Errorf("invalid semver %q: bad version segment %q", version, seg)
		}
		*nums[i] = n
	}
	return parts, nil
}

// compareSemverParsed returns -1, 0 or 1 as a is lower than, equal to or
// higher than b, following SemVer 2.0.0 precedence (build metadata ignored).
func compareSemverParsed(a, b semverParts) int {
	for _, d := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

// comparePrerelease orders prerelease strings per SemVer 2.0.0 §11: a
// version without a prerelease ranks higher; identifiers compare
// dot-by-dot, numeric ones numerically and below alphanumeric ones; a
// shorter prefix ranks lower. (A plain string comparison put rc.10 before
// rc.2.)
func comparePrerelease(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		case as[i] != bs[i]:
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
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

// semverCond is one condition of a constraint such as ">=1.0.0".
type semverCond struct {
	op  string
	ver semverParts
}

type semverConstraint []semverCond

// parseSemverConstraint parses comma-separated AND conditions, e.g.
// ">=1.0.0,<2.0.0". Operators: >= <= > < = ^ (same major) ~ (same
// major.minor); a bare version means "=".
func parseSemverConstraint(constraint string) (semverConstraint, error) {
	var out semverConstraint
	for _, cond := range strings.Split(constraint, ",") {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}
		op := "="
		for _, candidate := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
			if strings.HasPrefix(cond, candidate) {
				op = candidate
				cond = strings.TrimPrefix(cond, candidate)
				break
			}
		}
		v, err := parseSemver(strings.TrimSpace(cond))
		if err != nil {
			return nil, err
		}
		out = append(out, semverCond{op, v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty constraint")
	}
	return out, nil
}

func (c semverConstraint) match(v semverParts) bool {
	for _, cond := range c {
		cmp := compareSemverParsed(v, cond.ver)
		var ok bool
		switch cond.op {
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		case "=":
			ok = cmp == 0
		case "^":
			ok = v.Major == cond.ver.Major && cmp >= 0
		case "~":
			ok = v.Major == cond.ver.Major && v.Minor == cond.ver.Minor && cmp >= 0
		}
		if !ok {
			return false
		}
	}
	return true
}
