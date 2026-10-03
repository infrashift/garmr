// internal/engine/builtins.go
// Additional built-in functions for policy evaluation.
// These complement the original builtins in engine.go.
package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// registerExtendedBuiltins registers all extended built-in functions.
// Called from registerBuiltins() in engine.go.
func (e *Engine) registerExtendedBuiltins() {
	// Aggregate functions
	e.builtins["sum"] = builtinSum
	e.builtins["min"] = builtinMin
	e.builtins["max"] = builtinMax
	e.builtins["avg"] = builtinAvg

	// String manipulation
	e.builtins["trim"] = builtinTrim
	e.builtins["trimPrefix"] = builtinTrimPrefix
	e.builtins["trimSuffix"] = builtinTrimSuffix
	e.builtins["split"] = builtinSplit
	e.builtins["join"] = builtinJoin

	// Encoding
	e.builtins["base64Decode"] = builtinBase64Decode
	e.builtins["base64Encode"] = builtinBase64Encode

	// Time/duration
	e.builtins["duration"] = builtinDuration
	e.builtins["parseTime"] = builtinParseTime
	e.builtins["format"] = builtinFormat

	// Type checking
	e.builtins["typeOf"] = builtinTypeOf
	e.builtins["isType"] = builtinIsType

	// Object/map operators
	e.builtins["hasKey"] = builtinHasKey
	e.builtins["keys"] = builtinKeys
	e.builtins["values"] = builtinValues

	// Network (CIDR/IP)
	e.builtins["cidrContains"] = builtinCIDRContains
	e.builtins["cidrOverlap"] = builtinCIDROverlap
	e.builtins["ipVersion"] = builtinIPVersion

	// K8s units
	e.builtins["unitsParse"] = builtinUnitsParse

	// Lookup
	e.builtins["lookup"] = builtinLookup

	// Array operations
	e.builtins["flatten"] = builtinFlatten
	e.builtins["unique"] = builtinUnique
	e.builtins["sort"] = builtinSort
	e.builtins["filter"] = builtinFilter
}

// ============================================
// AGGREGATE FUNCTIONS
// ============================================

func builtinSum(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("sum requires at least 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("sum: argument must be an array")
	}
	var total float64
	for _, v := range arr {
		n, err := toFloat64(v)
		if err != nil {
			return nil, fmt.Errorf("sum: %w", err)
		}
		total += n
	}
	if isIntegral(total) {
		return int64(total), nil
	}
	return total, nil
}

func builtinMin(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("min requires at least 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("min: argument must be an array")
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("min: array is empty")
	}
	minVal, err := toFloat64(arr[0])
	if err != nil {
		return nil, fmt.Errorf("min: %w", err)
	}
	for _, v := range arr[1:] {
		n, err := toFloat64(v)
		if err != nil {
			return nil, fmt.Errorf("min: %w", err)
		}
		if n < minVal {
			minVal = n
		}
	}
	if isIntegral(minVal) {
		return int64(minVal), nil
	}
	return minVal, nil
}

func builtinMax(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("max requires at least 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("max: argument must be an array")
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("max: array is empty")
	}
	maxVal, err := toFloat64(arr[0])
	if err != nil {
		return nil, fmt.Errorf("max: %w", err)
	}
	for _, v := range arr[1:] {
		n, err := toFloat64(v)
		if err != nil {
			return nil, fmt.Errorf("max: %w", err)
		}
		if n > maxVal {
			maxVal = n
		}
	}
	if isIntegral(maxVal) {
		return int64(maxVal), nil
	}
	return maxVal, nil
}

func builtinAvg(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("avg requires at least 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("avg: argument must be an array")
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("avg: array is empty")
	}
	var total float64
	for _, v := range arr {
		n, err := toFloat64(v)
		if err != nil {
			return nil, fmt.Errorf("avg: %w", err)
		}
		total += n
	}
	return total / float64(len(arr)), nil
}

// ============================================
// STRING FUNCTIONS
// ============================================

func builtinTrim(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("trim requires at least 1 argument")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("trim: argument must be a string")
	}
	if len(args) >= 2 {
		cutset, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("trim: cutset must be a string")
		}
		return strings.Trim(s, cutset), nil
	}
	return strings.TrimSpace(s), nil
}

func builtinTrimPrefix(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("trimPrefix requires 2 arguments")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("trimPrefix: first argument must be a string")
	}
	prefix, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("trimPrefix: second argument must be a string")
	}
	return strings.TrimPrefix(s, prefix), nil
}

func builtinTrimSuffix(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("trimSuffix requires 2 arguments")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("trimSuffix: first argument must be a string")
	}
	suffix, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("trimSuffix: second argument must be a string")
	}
	return strings.TrimSuffix(s, suffix), nil
}

func builtinSplit(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("split requires 2 arguments")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("split: first argument must be a string")
	}
	sep, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("split: second argument must be a string")
	}
	parts := strings.Split(s, sep)
	result := make([]any, len(parts))
	for i, p := range parts {
		result[i] = p
	}
	return result, nil
}

func builtinJoin(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("join requires 2 arguments")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("join: first argument must be an array")
	}
	sep, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("join: second argument must be a string")
	}
	strs := make([]string, len(arr))
	for i, v := range arr {
		strs[i] = fmt.Sprintf("%v", v)
	}
	return strings.Join(strs, sep), nil
}

// ============================================
// ENCODING FUNCTIONS
// ============================================

func builtinBase64Decode(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("base64Decode requires 1 argument")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("base64Decode: argument must be a string")
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try URL-safe encoding
		decoded, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("base64Decode: %w", err)
		}
	}
	return string(decoded), nil
}

func builtinBase64Encode(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("base64Encode requires 1 argument")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("base64Encode: argument must be a string")
	}
	return base64.StdEncoding.EncodeToString([]byte(s)), nil
}

// ============================================
// TIME/DURATION FUNCTIONS
// ============================================

func builtinDuration(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("duration requires 1 argument")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("duration: argument must be a string")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, fmt.Errorf("duration: %w", err)
	}
	return d.Seconds(), nil
}

func builtinParseTime(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("parseTime requires at least 1 argument")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("parseTime: first argument must be a string")
	}

	layout := time.RFC3339
	if len(args) >= 2 {
		l, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("parseTime: second argument (layout) must be a string")
		}
		layout = l
	}

	t, err := time.Parse(layout, s)
	if err != nil {
		return nil, fmt.Errorf("parseTime: %w", err)
	}
	return t.Unix(), nil
}

func builtinFormat(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("format requires 2 arguments")
	}
	format, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("format: first argument must be a format string")
	}
	return fmt.Sprintf(format, args[1:]...), nil
}

// ============================================
// TYPE CHECKING FUNCTIONS
// ============================================

func builtinTypeOf(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("typeOf requires 1 argument")
	}
	return typeNameOf(args[0]), nil
}

func builtinIsType(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("isType requires 2 arguments (value, typeName)")
	}
	expectedType, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("isType: second argument must be a type name string")
	}
	return typeNameOf(args[0]) == expectedType, nil
}

func typeNameOf(v any) string {
	if v == nil {
		return "null"
	}
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int8, int16, int32, int64:
		return "number"
	case uint, uint8, uint16, uint32, uint64:
		return "number"
	case float32, float64:
		return "number"
	case []any, []string, []int, []float64:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// ============================================
// OBJECT/MAP FUNCTIONS
// ============================================

func builtinHasKey(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("hasKey requires 2 arguments (object, key)")
	}
	m, ok := args[0].(map[string]any)
	if !ok {
		return false, nil
	}
	key, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("hasKey: key must be a string")
	}
	_, exists := m[key]
	return exists, nil
}

func builtinKeys(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("keys requires 1 argument")
	}
	m, ok := args[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("keys: argument must be an object")
	}
	keys := make([]any, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].(string) < keys[j].(string)
	})
	return keys, nil
}

func builtinValues(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("values requires 1 argument")
	}
	m, ok := args[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("values: argument must be an object")
	}
	// Return values in sorted key order for determinism
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals := make([]any, len(keys))
	for i, k := range keys {
		vals[i] = m[k]
	}
	return vals, nil
}

// ============================================
// NETWORK / CIDR FUNCTIONS
// ============================================

func builtinCIDRContains(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("cidrContains requires 2 arguments (cidr, ip)")
	}
	cidrStr, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("cidrContains: first argument must be a CIDR string")
	}
	ipStr, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("cidrContains: second argument must be an IP string")
	}

	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("cidrContains: invalid CIDR: %w", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("cidrContains: invalid IP address: %s", ipStr)
	}

	return network.Contains(ip), nil
}

func builtinCIDROverlap(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("cidrOverlap requires 2 arguments (cidr1, cidr2)")
	}
	cidr1Str, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("cidrOverlap: first argument must be a CIDR string")
	}
	cidr2Str, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("cidrOverlap: second argument must be a CIDR string")
	}

	_, network1, err := net.ParseCIDR(cidr1Str)
	if err != nil {
		return nil, fmt.Errorf("cidrOverlap: invalid first CIDR: %w", err)
	}
	_, network2, err := net.ParseCIDR(cidr2Str)
	if err != nil {
		return nil, fmt.Errorf("cidrOverlap: invalid second CIDR: %w", err)
	}

	return network1.Contains(network2.IP) || network2.Contains(network1.IP), nil
}

func builtinIPVersion(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("ipVersion requires 1 argument")
	}
	ipStr, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("ipVersion: argument must be an IP string")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("ipVersion: invalid IP address: %s", ipStr)
	}

	if ip.To4() != nil {
		return int64(4), nil
	}
	return int64(6), nil
}

// ============================================
// K8S UNITS PARSING
// ============================================

// builtinUnitsParse parses Kubernetes resource quantity strings.
// CPU: "500m" → 0.5, "2" → 2.0
// Memory: "1Gi" → 1073741824, "100Mi" → 104857600, "500Ki" → 512000
func builtinUnitsParse(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("unitsParse requires 1 argument")
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("unitsParse: argument must be a string")
	}

	return parseK8sQuantity(s)
}

// parseK8sQuantity parses a Kubernetes resource quantity string into a float64.
func parseK8sQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty quantity string")
	}

	// Binary suffixes (Ki, Mi, Gi, Ti, Pi, Ei)
	binarySuffixes := map[string]float64{
		"Ki": 1024,
		"Mi": 1024 * 1024,
		"Gi": 1024 * 1024 * 1024,
		"Ti": 1024 * 1024 * 1024 * 1024,
		"Pi": 1024 * 1024 * 1024 * 1024 * 1024,
		"Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
	}

	// Decimal suffixes
	decimalSuffixes := map[string]float64{
		"n": 1e-9,
		"u": 1e-6,
		"m": 1e-3,
		"k": 1e3,
		"M": 1e6,
		"G": 1e9,
		"T": 1e12,
		"P": 1e15,
		"E": 1e18,
	}

	// Try binary suffixes first (2-char)
	if len(s) >= 3 {
		suffix := s[len(s)-2:]
		if multiplier, ok := binarySuffixes[suffix]; ok {
			numStr := s[:len(s)-2]
			num, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid quantity: %s", s)
			}
			return num * multiplier, nil
		}
	}

	// Try decimal suffixes (1-char)
	if len(s) >= 2 {
		suffix := s[len(s)-1:]
		if multiplier, ok := decimalSuffixes[suffix]; ok {
			numStr := s[:len(s)-1]
			num, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid quantity: %s", s)
			}
			return num * multiplier, nil
		}
	}

	// Plain number
	num, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid quantity: %s", s)
	}
	return num, nil
}

// ============================================
// LOOKUP FUNCTIONS
// ============================================

func builtinLookup(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("lookup requires 2 arguments (object, path)")
	}
	obj, ok := args[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("lookup: first argument must be an object")
	}
	path, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("lookup: second argument must be a path string")
	}

	return lookupPath(obj, path), nil
}

// lookupPath navigates a nested map using dot-notation path.
func lookupPath(obj map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var current any = obj

	for _, part := range parts {
		if part == "" {
			continue
		}

		switch v := current.(type) {
		case map[string]any:
			val, exists := v[part]
			if !exists {
				return nil
			}
			current = val
		default:
			return nil
		}
	}

	return current
}

// ============================================
// ARRAY FUNCTIONS
// ============================================

func builtinFlatten(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("flatten requires 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("flatten: argument must be an array")
	}
	return flattenSlice(arr), nil
}

func flattenSlice(arr []any) []any {
	var result []any
	for _, v := range arr {
		if inner, ok := toSlice(v); ok {
			result = append(result, flattenSlice(inner)...)
		} else {
			result = append(result, v)
		}
	}
	return result
}

func builtinUnique(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("unique requires 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("unique: argument must be an array")
	}

	seen := make(map[string]bool)
	var result []any
	for _, v := range arr {
		key := setKey(v)
		if !seen[key] {
			seen[key] = true
			result = append(result, v)
		}
	}
	return result, nil
}

func builtinSort(_ context.Context, args ...any) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("sort requires 1 argument")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("sort: argument must be an array")
	}

	// Make a copy to avoid mutating the original
	sorted := make([]any, len(arr))
	copy(sorted, arr)

	sort.SliceStable(sorted, func(i, j int) bool {
		if cmp, ok := orderValues(sorted[i], sorted[j]); ok {
			return cmp < 0
		}
		// Mixed kinds: group by kind so the order is still deterministic.
		return valueKind(sorted[i]) < valueKind(sorted[j])
	})

	return sorted, nil
}

func builtinFilter(_ context.Context, args ...any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("filter requires 2 arguments (array, value)")
	}
	arr, ok := toSlice(args[0])
	if !ok {
		return nil, fmt.Errorf("filter: first argument must be an array")
	}

	filterVal := args[1]
	var result []any
	for _, v := range arr {
		if eqValues(v, filterVal) {
			result = append(result, v)
		}
	}
	if result == nil {
		result = []any{}
	}
	return result, nil
}

// ============================================
// HELPER FUNCTIONS
// ============================================

// toSlice converts various slice types to []any.
func toSlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		result := make([]any, len(s))
		for i, v := range s {
			result[i] = v
		}
		return result, true
	case []int:
		result := make([]any, len(s))
		for i, v := range s {
			result[i] = v
		}
		return result, true
	case []float64:
		result := make([]any, len(s))
		for i, v := range s {
			result[i] = v
		}
		return result, true
	case []int64:
		result := make([]any, len(s))
		for i, v := range s {
			result[i] = v
		}
		return result, true
	default:
		return nil, false
	}
}

// toFloat64 converts a numeric value to float64.
func toFloat64(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case int32:
		return float64(n), nil
	case int16:
		return float64(n), nil
	case int8:
		return float64(n), nil
	case uint:
		return float64(n), nil
	case uint64:
		return float64(n), nil
	case uint32:
		return float64(n), nil
	case uint16:
		return float64(n), nil
	case uint8:
		return float64(n), nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot convert string %q to number", n)
		}
		return f, nil
	case json.Number:
		return n.Float64()
	default:
		return 0, fmt.Errorf("cannot convert %T to number", v)
	}
}

// isIntegral checks if a float64 is an integer value.
func isIntegral(f float64) bool {
	return f == math.Trunc(f)
}
