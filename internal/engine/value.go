package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Values seen during evaluation are JSON-shaped: map[string]any, []any,
// string, bool, nil, and numbers. Numbers may be any Go numeric kind (JSON
// decoding yields float64, YAML and CUE yield int) and compare by value.

// asNumber returns v as a float64 when v is a number. Strings are never
// numbers: "1" and 1 are different values.
func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case int32:
		return float64(n), true
	case int16:
		return float64(n), true
	case int8:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint8:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// eqValues is strict, JSON-typed equality: numbers compare by value
// (1 == 1.0), every other pair must have the same type, and lists and maps
// compare element-wise.
//
// It replaces a comparison that parsed strings as numbers and otherwise fell
// back to fmt's %v rendering, under which "1" == 1, true == "true" and
// nil == "<nil>" all held.
func eqValues(a, b any) bool {
	if af, ok := asNumber(a); ok {
		bf, ok := asNumber(b)
		return ok && af == bf
	}
	switch av := a.(type) {
	case nil:
		return b == nil
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !eqValues(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok || !eqValues(x, y) {
				return false
			}
		}
		return true
	}
	return false
}

// setKey maps a value to a string such that eqValues(a, b) implies
// setKey(a) == setKey(b), for use as a hash-set key.
func setKey(v any) string {
	if f, ok := asNumber(v); ok {
		return "n:" + strconv.FormatFloat(f, 'g', -1, 64)
	}
	switch x := v.(type) {
	case nil:
		return "z"
	case string:
		return "s:" + x
	case bool:
		if x {
			return "b:1"
		}
		return "b:0"
	}
	// Composite values: canonical JSON (encoding/json sorts map keys).
	// Numbers inside are normalized through float64 so 1 and 1.0 agree.
	b, err := json.Marshal(normalizeNumbers(v))
	if err != nil {
		return fmt.Sprintf("x:%v", v)
	}
	return "j:" + string(b)
}

func normalizeNumbers(v any) any {
	if f, ok := asNumber(v); ok {
		return f
	}
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeNumbers(x[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalizeNumbers(e)
		}
		return out
	}
	return v
}

// orderValues orders two numbers, or two strings. Any other pair is not
// orderable.
func orderValues(a, b any) (int, bool) {
	if af, ok := asNumber(a); ok {
		bf, ok := asNumber(b)
		if !ok {
			return 0, false
		}
		switch {
		case af < bf:
			return -1, true
		case af > bf:
			return 1, true
		}
		return 0, true
	}
	as, ok := a.(string)
	if !ok {
		return 0, false
	}
	bs, ok := b.(string)
	if !ok {
		return 0, false
	}
	switch {
	case as < bs:
		return -1, true
	case as > bs:
		return 1, true
	}
	return 0, true
}

// normalizeInput returns input in canonical JSON shape. Input decoded from
// JSON (the server path) is already canonical and is returned unchanged
// without allocating; anything else (typed slices, structs, time.Time from
// Go callers) is round-tripped through JSON once.
func normalizeInput(input map[string]any) (map[string]any, error) {
	if canonical(input) {
		return input, nil
	}
	b, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return out, nil
}

func canonical(v any) bool {
	switch x := v.(type) {
	case nil, string, bool:
		return true
	case map[string]any:
		for _, e := range x {
			if !canonical(e) {
				return false
			}
		}
		return true
	case []any:
		for _, e := range x {
			if !canonical(e) {
				return false
			}
		}
		return true
	}
	_, ok := asNumber(v)
	return ok
}

// render formats a value for a violation message.
func render(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}
