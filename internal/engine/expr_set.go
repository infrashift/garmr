package engine

import (
	"fmt"
	"strconv"

	"cuelang.org/go/cue"
)

// Advanced set operators for the match expression family:
//
//	match: {path: "spec.ports", unique: true}
//	match: {path: "spec.containers", uniqueBy: "name"}
//	match: {path: "spec.priorities", sorted: "asc"}
//	match: {path: "spec.regions", containsAll: ["us-east-1", "eu-west-1"]}
//	match: {path: "spec.zones", subsetOf: ["zone-a", "zone-b", "zone-c"]}
//
// Element equality follows valuesEqual semantics (numeric-aware, so 1 and
// 1.0 are the same value).

// setKey normalizes a value into a map key with valuesEqual semantics:
// values that valuesEqual considers equal produce the same key.
func setKey(v any) string {
	if f, ok := toFloatOk(v); ok {
		return "n:" + strconv.FormatFloat(f, 'g', -1, 64)
	}
	// fmt sorts map keys, so composite values stringify deterministically.
	return "v:" + fmt.Sprintf("%v", v)
}

// decodeList decodes a CUE value into a Go slice, reporting whether the
// value is an array at all.
func decodeList(fieldVal cue.Value, path string) ([]any, string) {
	if fieldVal.Kind() != cue.ListKind {
		return nil, fmt.Sprintf("path '%s' is not an array", path)
	}
	var items []any
	if err := fieldVal.Decode(&items); err != nil {
		return nil, fmt.Sprintf("path '%s' could not be decoded as an array: %v", path, err)
	}
	return items, ""
}

// evaluateUnique checks that an array has no duplicate values.
func (e *Engine) evaluateUnique(fieldVal cue.Value, uniqueVal cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	required, err := uniqueVal.Bool()
	if err != nil {
		return false, bindings, "'unique' must be a boolean"
	}
	if !required {
		// unique: false places no constraint on the array
		return true, bindings, ""
	}

	items, errMsg := decodeList(fieldVal, path)
	if errMsg != "" {
		return false, bindings, errMsg
	}

	seen := make(map[string]bool, len(items))
	for _, item := range items {
		key := setKey(item)
		if seen[key] {
			return false, bindings, fmt.Sprintf("'%s' contains duplicate value %v", path, item)
		}
		seen[key] = true
	}
	return true, bindings, ""
}

// evaluateUniqueBy checks that an array of objects has no duplicate values
// for the given field (dot-notation paths supported).
func (e *Engine) evaluateUniqueBy(fieldVal cue.Value, uniqueByVal cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	field, err := uniqueByVal.String()
	if err != nil || field == "" {
		return false, bindings, "'uniqueBy' must be a non-empty field path"
	}

	if fieldVal.Kind() != cue.ListKind {
		return false, bindings, fmt.Sprintf("path '%s' is not an array", path)
	}

	iter, _ := fieldVal.List()
	seen := make(map[string]bool)
	index := 0
	for iter.Next() {
		keyVal := iter.Value().LookupPath(cue.ParsePath(field))
		if !keyVal.Exists() {
			return false, bindings, fmt.Sprintf("'%s[%d]' has no field '%s'", path, index, field)
		}
		var v any
		if err := keyVal.Decode(&v); err != nil {
			return false, bindings, fmt.Sprintf("'%s[%d].%s' could not be decoded: %v", path, index, field, err)
		}
		key := setKey(v)
		if seen[key] {
			return false, bindings, fmt.Sprintf("'%s' contains duplicate %s %v", path, field, v)
		}
		seen[key] = true
		index++
	}
	return true, bindings, ""
}

// evaluateSorted checks that an array is sorted in the given order
// ("asc" or "desc"). Elements are compared numerically when both sides are
// numeric, otherwise as strings; composite elements are not comparable.
func (e *Engine) evaluateSorted(fieldVal cue.Value, sortedVal cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	order, err := sortedVal.String()
	if err != nil || (order != "asc" && order != "desc") {
		return false, bindings, "'sorted' must be \"asc\" or \"desc\""
	}

	items, errMsg := decodeList(fieldVal, path)
	if errMsg != "" {
		return false, bindings, errMsg
	}

	for i := 1; i < len(items); i++ {
		cmp, ok := compareScalars(items[i-1], items[i])
		if !ok {
			return false, bindings, fmt.Sprintf("'%s' contains values that cannot be ordered", path)
		}
		if (order == "asc" && cmp > 0) || (order == "desc" && cmp < 0) {
			return false, bindings, fmt.Sprintf("'%s' is not sorted in %sending order at index %d", path, order, i)
		}
	}
	return true, bindings, ""
}

// compareScalars orders two scalar values: numerically when both are
// numeric, otherwise by string representation. Composite values (maps,
// arrays) are not orderable.
func compareScalars(a, b any) (int, bool) {
	switch a.(type) {
	case map[string]any, []any:
		return 0, false
	}
	switch b.(type) {
	case map[string]any, []any:
		return 0, false
	}

	af, aok := toFloatOk(a)
	bf, bok := toFloatOk(b)
	if aok && bok {
		switch {
		case af < bf:
			return -1, true
		case af > bf:
			return 1, true
		default:
			return 0, true
		}
	}

	as := fmt.Sprintf("%v", a)
	bs := fmt.Sprintf("%v", b)
	switch {
	case as < bs:
		return -1, true
	case as > bs:
		return 1, true
	default:
		return 0, true
	}
}

// evaluateContainsAll checks that an array contains every required value
// (superset check).
func (e *Engine) evaluateContainsAll(fieldVal cue.Value, containsAllVal cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	var required []any
	if err := containsAllVal.Decode(&required); err != nil {
		return false, bindings, "'containsAll' must be a list"
	}

	items, errMsg := decodeList(fieldVal, path)
	if errMsg != "" {
		return false, bindings, errMsg
	}

	present := make(map[string]bool, len(items))
	for _, item := range items {
		present[setKey(item)] = true
	}

	var missing []string
	for _, want := range required {
		if !present[setKey(want)] {
			missing = append(missing, fmt.Sprintf("%v", want))
		}
	}
	if len(missing) > 0 {
		return false, bindings, fmt.Sprintf("'%s' is missing required values: %v", path, missing)
	}
	return true, bindings, ""
}

// evaluateSubsetOf checks that every array element is from an allowed list
// (subset check).
func (e *Engine) evaluateSubsetOf(fieldVal cue.Value, subsetOfVal cue.Value, path string) (bool, map[string]any, string) {
	bindings := make(map[string]any)

	var allowed []any
	if err := subsetOfVal.Decode(&allowed); err != nil {
		return false, bindings, "'subsetOf' must be a list"
	}

	items, errMsg := decodeList(fieldVal, path)
	if errMsg != "" {
		return false, bindings, errMsg
	}

	allowedSet := make(map[string]bool, len(allowed))
	for _, v := range allowed {
		allowedSet[setKey(v)] = true
	}

	for _, item := range items {
		if !allowedSet[setKey(item)] {
			return false, bindings, fmt.Sprintf("'%s' contains value %v not in the allowed set", path, item)
		}
	}
	return true, bindings, ""
}
