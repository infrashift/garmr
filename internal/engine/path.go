package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// pathSeg is one step of a field path: a map key, a list index, or a
// projection over every list element ([*]).
type pathSeg struct {
	key   string
	index int
	isIdx bool
	isAll bool
}

// fieldPath is a pre-parsed field path. Paths are parsed once when a policy
// is compiled, so evaluation is a plain walk over the input.
type fieldPath struct {
	raw  string
	segs []pathSeg
}

func (p fieldPath) String() string { return p.raw }

// parsePath parses a dot-separated field path:
//
//	spec.containers                         plain keys
//	metadata.labels."app.kubernetes.io/name" quoted key (may contain dots)
//	spec.containers[0].image                list index
//	spec.containers[*].image                projection: one value per element
//
// Unquoted keys may contain any character except '.', '"', '[' and ']', so
// keys such as "host-network" and "_index" resolve as written. (Paths used to
// go through cue.ParsePath, which silently failed to resolve both.)
func parsePath(s string) (fieldPath, error) {
	p := fieldPath{raw: s}
	if s == "" {
		return p, fmt.Errorf("empty path")
	}
	i := 0
	expectKey := true
	for i < len(s) {
		switch {
		case s[i] == '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return p, fmt.Errorf("path %q: unterminated '['", s)
			}
			if s[i+1:i+end] == "*" {
				p.segs = append(p.segs, pathSeg{isAll: true})
			} else {
				n, err := strconv.Atoi(s[i+1 : i+end])
				if err != nil || n < 0 {
					return p, fmt.Errorf("path %q: list index must be a non-negative integer or *", s)
				}
				p.segs = append(p.segs, pathSeg{index: n, isIdx: true})
			}
			i += end + 1
			expectKey = false
		case s[i] == '.':
			if expectKey {
				return p, fmt.Errorf("path %q: empty segment", s)
			}
			i++
			expectKey = true
			if i == len(s) {
				return p, fmt.Errorf("path %q: trailing '.'", s)
			}
		case !expectKey:
			return p, fmt.Errorf("path %q: expected '.' or '[' at offset %d", s, i)
		case s[i] == '"':
			end := i + 1
			for end < len(s) && s[end] != '"' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(s) {
				return p, fmt.Errorf("path %q: unterminated quoted segment", s)
			}
			key, err := strconv.Unquote(s[i : end+1])
			if err != nil {
				return p, fmt.Errorf("path %q: invalid quoted segment: %w", s, err)
			}
			p.segs = append(p.segs, pathSeg{key: key})
			i = end + 1
			expectKey = false
		default:
			end := i
			for end < len(s) && s[end] != '.' && s[end] != '[' && s[end] != '"' && s[end] != ']' {
				end++
			}
			if end == i {
				return p, fmt.Errorf("path %q: unexpected %q at offset %d", s, s[i], i)
			}
			p.segs = append(p.segs, pathSeg{key: s[i:end]})
			i = end
			expectKey = false
		}
	}
	return p, nil
}

// walk resolves the segments of p starting at v. found is false when any step
// is missing; a present null resolves to (nil, true).
//
// A projection ([*]) resolves to a list with one value per element: the rest
// of the path walked from that element, or null where the element lacks it,
// so an aggregate over a partly-missing field fails rather than silently
// skipping. Nested projections flatten; an element whose nested list is
// missing contributes no values. A projection over something that is not a
// list does not resolve.
func (p fieldPath) walk(v any, segs []pathSeg) (any, bool) {
	for i, seg := range segs {
		if seg.isAll {
			list, ok := v.([]any)
			if !ok {
				return nil, false
			}
			rest := segs[i+1:]
			nested := false
			for _, r := range rest {
				nested = nested || r.isAll
			}
			out := make([]any, 0, len(list))
			for _, e := range list {
				r, found := p.walk(e, rest)
				switch {
				case nested && found:
					out = append(out, r.([]any)...)
				case !nested:
					out = append(out, r) // nil when not found
				}
			}
			return out, true
		}
		if seg.isIdx {
			list, ok := v.([]any)
			if !ok || seg.index >= len(list) {
				return nil, false
			}
			v = list[seg.index]
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[seg.key]; !ok {
			return nil, false
		}
	}
	return v, true
}
