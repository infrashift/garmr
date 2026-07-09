package engine

import (
	"context"
	"testing"
)

var ctx = context.Background()

// --- Original builtins (engine.go) ---

func TestBuiltinLen(t *testing.T) {
	tests := []struct {
		name string
		arg  any
		want int
	}{
		{"string", "hello", 5},
		{"array", []any{1, 2, 3}, 3},
		{"map", map[string]any{"a": 1, "b": 2}, 2},
		{"empty string", "", 0},
		{"empty array", []any{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := builtinLen(ctx, tt.arg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.want {
				t.Errorf("len(%v) = %v, want %v", tt.arg, result, tt.want)
			}
		})
	}
}

func TestBuiltinLen_Error(t *testing.T) {
	_, err := builtinLen(ctx, 42)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
	_, err = builtinLen(ctx)
	if err == nil {
		t.Error("expected error for no args")
	}
}

func TestBuiltinLower(t *testing.T) {
	result, err := builtinLower(ctx, "HELLO")
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello" {
		t.Errorf("lower(HELLO) = %v, want hello", result)
	}
}

func TestBuiltinUpper(t *testing.T) {
	result, err := builtinUpper(ctx, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if result != "HELLO" {
		t.Errorf("upper(hello) = %v, want HELLO", result)
	}
}

func TestBuiltinContains(t *testing.T) {
	result, err := builtinContains(ctx, "hello world", "world")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true")
	}

	result, err = builtinContains(ctx, "hello", "xyz")
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected false")
	}
}

func TestBuiltinStartsWith(t *testing.T) {
	result, err := builtinStartsWith(ctx, "hello world", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true")
	}
}

func TestBuiltinEndsWith(t *testing.T) {
	result, err := builtinEndsWith(ctx, "hello world", "world")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true")
	}
}

func TestBuiltinMatches(t *testing.T) {
	result, err := builtinMatches(ctx, "hello-123", `^hello-\d+$`)
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true")
	}

	result, err = builtinMatches(ctx, "goodbye", `^hello`)
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected false")
	}
}

func TestBuiltinNow(t *testing.T) {
	result, err := builtinNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := result.(string)
	if !ok {
		t.Fatalf("expected string, got %T", result)
	}
	if len(s) < 10 {
		t.Errorf("now() returned too short string: %s", s)
	}
}

// --- Aggregate functions ---

func TestBuiltinSum(t *testing.T) {
	tests := []struct {
		name string
		args []any
		want any
	}{
		{"ints", []any{[]any{1.0, 2.0, 3.0}}, int64(6)},
		{"floats", []any{[]any{1.5, 2.5}}, int64(4)}, // 1.5 + 2.5 = 4.0, integral → int64
		{"single", []any{[]any{42.0}}, int64(42)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := builtinSum(ctx, tt.args...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.want {
				t.Errorf("sum = %v (%T), want %v (%T)", result, result, tt.want, tt.want)
			}
		})
	}
}

func TestBuiltinSum_EmptyArray(t *testing.T) {
	result, err := builtinSum(ctx, []any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != int64(0) {
		t.Errorf("sum([]) = %v, want 0", result)
	}
}

func TestBuiltinSum_Error(t *testing.T) {
	_, err := builtinSum(ctx)
	if err == nil {
		t.Error("expected error for no args")
	}
	_, err = builtinSum(ctx, "not an array")
	if err == nil {
		t.Error("expected error for non-array arg")
	}
}

func TestBuiltinMin(t *testing.T) {
	result, err := builtinMin(ctx, []any{3.0, 1.0, 2.0})
	if err != nil {
		t.Fatal(err)
	}
	if result != int64(1) {
		t.Errorf("min = %v, want 1", result)
	}
}

func TestBuiltinMin_EmptyArray(t *testing.T) {
	_, err := builtinMin(ctx, []any{})
	if err == nil {
		t.Error("expected error for empty array")
	}
}

func TestBuiltinMax(t *testing.T) {
	result, err := builtinMax(ctx, []any{3.0, 1.0, 2.0})
	if err != nil {
		t.Fatal(err)
	}
	if result != int64(3) {
		t.Errorf("max = %v, want 3", result)
	}
}

func TestBuiltinAvg(t *testing.T) {
	result, err := builtinAvg(ctx, []any{2.0, 4.0, 6.0})
	if err != nil {
		t.Fatal(err)
	}
	if result != 4.0 {
		t.Errorf("avg = %v, want 4.0", result)
	}
}

// --- String manipulation ---

func TestBuiltinTrim(t *testing.T) {
	result, err := builtinTrim(ctx, "  hello  ")
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello" {
		t.Errorf("trim = %v, want hello", result)
	}

	// With cutset
	result, err = builtinTrim(ctx, "xxhelloxx", "x")
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello" {
		t.Errorf("trim with cutset = %v, want hello", result)
	}
}

func TestBuiltinTrimPrefix(t *testing.T) {
	result, err := builtinTrimPrefix(ctx, "prefix-value", "prefix-")
	if err != nil {
		t.Fatal(err)
	}
	if result != "value" {
		t.Errorf("trimPrefix = %v, want value", result)
	}
}

func TestBuiltinTrimSuffix(t *testing.T) {
	result, err := builtinTrimSuffix(ctx, "value-suffix", "-suffix")
	if err != nil {
		t.Fatal(err)
	}
	if result != "value" {
		t.Errorf("trimSuffix = %v, want value", result)
	}
}

func TestBuiltinSplit(t *testing.T) {
	result, err := builtinSplit(ctx, "a,b,c", ",")
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := result.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", result)
	}
	if len(arr) != 3 || arr[0] != "a" || arr[2] != "c" {
		t.Errorf("split = %v, want [a b c]", arr)
	}
}

func TestBuiltinJoin(t *testing.T) {
	result, err := builtinJoin(ctx, []any{"a", "b", "c"}, ",")
	if err != nil {
		t.Fatal(err)
	}
	if result != "a,b,c" {
		t.Errorf("join = %v, want a,b,c", result)
	}
}

func TestBuiltinRegex(t *testing.T) {
	result, err := builtinRegex(ctx, `^\d+$`, "12345")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true")
	}

	result, err = builtinRegex(ctx, `^\d+$`, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected false")
	}
}

func TestBuiltinRegex_InvalidPattern(t *testing.T) {
	_, err := builtinRegex(ctx, `[invalid`, "test")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

// --- Encoding ---

func TestBuiltinBase64_RoundTrip(t *testing.T) {
	encoded, err := builtinBase64Encode(ctx, "hello world")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := builtinBase64Decode(ctx, encoded.(string))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != "hello world" {
		t.Errorf("round trip failed: got %v", decoded)
	}
}

func TestBuiltinBase64Decode_Invalid(t *testing.T) {
	_, err := builtinBase64Decode(ctx, "!!!not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// --- Time/Duration ---

func TestBuiltinDuration(t *testing.T) {
	result, err := builtinDuration(ctx, "1h30m")
	if err != nil {
		t.Fatal(err)
	}
	if result != 5400.0 {
		t.Errorf("duration(1h30m) = %v, want 5400", result)
	}
}

func TestBuiltinDuration_Invalid(t *testing.T) {
	_, err := builtinDuration(ctx, "invalid")
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestBuiltinParseTime(t *testing.T) {
	result, err := builtinParseTime(ctx, "2024-01-15T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.(int64); !ok {
		t.Errorf("expected int64 unix timestamp, got %T", result)
	}
}

func TestBuiltinFormat(t *testing.T) {
	result, err := builtinFormat(ctx, "hello %s, you are %d", "world", 42)
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello world, you are 42" {
		t.Errorf("format = %v", result)
	}
}

// --- Type checking ---

func TestBuiltinTypeOf(t *testing.T) {
	tests := []struct {
		arg  any
		want string
	}{
		{"hello", "string"},
		{42.0, "number"},
		{true, "boolean"},
		{[]any{1}, "array"},
		{map[string]any{}, "object"},
		{nil, "null"},
	}
	for _, tt := range tests {
		result, err := builtinTypeOf(ctx, tt.arg)
		if err != nil {
			t.Fatal(err)
		}
		if result != tt.want {
			t.Errorf("typeOf(%v) = %v, want %v", tt.arg, result, tt.want)
		}
	}
}

func TestBuiltinIsType(t *testing.T) {
	result, err := builtinIsType(ctx, "hello", "string")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true for string is string")
	}

	result, err = builtinIsType(ctx, 42.0, "string")
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected false for number is string")
	}
}

// --- Object/map ---

func TestBuiltinHasKey(t *testing.T) {
	m := map[string]any{"name": "test", "count": 1}
	result, err := builtinHasKey(ctx, m, "name")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected true for existing key")
	}

	result, err = builtinHasKey(ctx, m, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected false for missing key")
	}
}

func TestBuiltinKeys(t *testing.T) {
	m := map[string]any{"b": 2, "a": 1}
	result, err := builtinKeys(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	keys := result.([]any)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	// Should be sorted
	if keys[0] != "a" || keys[1] != "b" {
		t.Errorf("keys = %v, want [a b]", keys)
	}
}

func TestBuiltinValues(t *testing.T) {
	m := map[string]any{"b": 2, "a": 1}
	result, err := builtinValues(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	vals := result.([]any)
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d", len(vals))
	}
	// Values in sorted key order: a=1, b=2
	if vals[0] != 1 || vals[1] != 2 {
		t.Errorf("values = %v, want [1 2]", vals)
	}
}

// --- Network ---

func TestBuiltinCIDRContains(t *testing.T) {
	result, err := builtinCIDRContains(ctx, "10.0.0.0/8", "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected 10.1.2.3 to be in 10.0.0.0/8")
	}

	result, err = builtinCIDRContains(ctx, "10.0.0.0/8", "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected 192.168.1.1 to not be in 10.0.0.0/8")
	}
}

func TestBuiltinCIDRContains_IPv6(t *testing.T) {
	result, err := builtinCIDRContains(ctx, "2001:db8::/32", "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected IPv6 address to be in subnet")
	}
}

func TestBuiltinCIDROverlap(t *testing.T) {
	result, err := builtinCIDROverlap(ctx, "10.0.0.0/8", "10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if result != true {
		t.Error("expected overlapping CIDRs")
	}

	result, err = builtinCIDROverlap(ctx, "10.0.0.0/8", "192.168.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if result != false {
		t.Error("expected non-overlapping CIDRs")
	}
}

func TestBuiltinIPVersion(t *testing.T) {
	result, err := builtinIPVersion(ctx, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result != int64(4) {
		t.Errorf("expected IPv4 (4), got %v", result)
	}

	result, err = builtinIPVersion(ctx, "::1")
	if err != nil {
		t.Fatal(err)
	}
	if result != int64(6) {
		t.Errorf("expected IPv6 (6), got %v", result)
	}
}

func TestBuiltinIPVersion_Invalid(t *testing.T) {
	_, err := builtinIPVersion(ctx, "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

// --- K8s Units ---

func TestBuiltinUnitsParse(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"500m", 0.5},
		{"1Gi", 1024 * 1024 * 1024},
		{"100Mi", 100 * 1024 * 1024},
		{"2.5", 2.5},
		{"1000m", 1.0},
		{"500Ki", 500 * 1024},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := builtinUnitsParse(ctx, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			f, ok := result.(float64)
			if !ok {
				t.Fatalf("expected float64, got %T", result)
			}
			if f != tt.want {
				t.Errorf("unitsParse(%q) = %v, want %v", tt.input, f, tt.want)
			}
		})
	}
}

func TestBuiltinUnitsParse_Error(t *testing.T) {
	_, err := builtinUnitsParse(ctx, "")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

// --- Lookup ---

func TestBuiltinLookup(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				"app": "nginx",
			},
		},
	}
	result, err := builtinLookup(ctx, obj, "metadata.labels.app")
	if err != nil {
		t.Fatal(err)
	}
	if result != "nginx" {
		t.Errorf("lookup = %v, want nginx", result)
	}

	// Missing path
	result, err = builtinLookup(ctx, obj, "metadata.missing.path")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("lookup for missing path = %v, want nil", result)
	}
}

// --- Array operations ---

func TestBuiltinFlatten(t *testing.T) {
	result, err := builtinFlatten(ctx, []any{[]any{1, 2}, []any{3, []any{4, 5}}})
	if err != nil {
		t.Fatal(err)
	}
	arr := result.([]any)
	if len(arr) != 5 {
		t.Errorf("expected 5 elements, got %d: %v", len(arr), arr)
	}
}

func TestBuiltinUnique(t *testing.T) {
	result, err := builtinUnique(ctx, []any{"a", "b", "a", "c", "b"})
	if err != nil {
		t.Fatal(err)
	}
	arr := result.([]any)
	if len(arr) != 3 {
		t.Errorf("expected 3 unique elements, got %d: %v", len(arr), arr)
	}
}

func TestBuiltinSort(t *testing.T) {
	result, err := builtinSort(ctx, []any{3.0, 1.0, 2.0})
	if err != nil {
		t.Fatal(err)
	}
	arr := result.([]any)
	if arr[0] != 1.0 || arr[1] != 2.0 || arr[2] != 3.0 {
		t.Errorf("sort = %v, want [1 2 3]", arr)
	}
}

func TestBuiltinFilter(t *testing.T) {
	result, err := builtinFilter(ctx, []any{"a", "b", "a", "c"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	arr := result.([]any)
	if len(arr) != 2 {
		t.Errorf("expected 2 matches, got %d: %v", len(arr), arr)
	}
}

func TestBuiltinFilter_NoMatch(t *testing.T) {
	result, err := builtinFilter(ctx, []any{"a", "b"}, "z")
	if err != nil {
		t.Fatal(err)
	}
	arr := result.([]any)
	if len(arr) != 0 {
		t.Errorf("expected 0 matches, got %d", len(arr))
	}
}

// --- Semver ---

func TestBuiltinSemverCompare(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int64
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.2.0", "1.1.0", 1},
		{"1.0.1", "1.0.0", 1},
		{"v1.0.0", "1.0.0", 0},
		// Prerelease precedence (semver spec): a prerelease sorts before
		// the release. The old duplicate parser stripped prereleases and
		// treated these as equal.
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
	}
	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			result, err := builtinSemverCompare(ctx, tt.v1, tt.v2)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.want {
				t.Errorf("semver(%s, %s) = %v, want %v", tt.v1, tt.v2, result, tt.want)
			}
		})
	}

	if _, err := builtinSemverCompare(ctx, "garbage", "1.0.0"); err == nil {
		t.Error("expected error for invalid semver operand")
	}
}

// --- JSON Path ---

func TestBuiltinJSONPath(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"name": "test",
		},
	}
	result, err := builtinJSONPath(ctx, obj, "metadata.name")
	if err != nil {
		t.Fatal(err)
	}
	if result != "test" {
		t.Errorf("jsonPath = %v, want test", result)
	}
}

func TestBuiltinJSONPath_FromString(t *testing.T) {
	result, err := builtinJSONPath(ctx, `{"name": "test"}`, "name")
	if err != nil {
		t.Fatal(err)
	}
	if result != "test" {
		t.Errorf("jsonPath from string = %v, want test", result)
	}
}

// --- Error cases ---

func TestBuiltinErrorCases(t *testing.T) {
	tests := []struct {
		name string
		fn   BuiltinFunc
		args []any
	}{
		{"sum no args", builtinSum, nil},
		{"min no args", builtinMin, nil},
		{"max no args", builtinMax, nil},
		{"avg no args", builtinAvg, nil},
		{"trim no args", builtinTrim, nil},
		{"trimPrefix no args", builtinTrimPrefix, nil},
		{"trimSuffix no args", builtinTrimSuffix, nil},
		{"split no args", builtinSplit, nil},
		{"join no args", builtinJoin, nil},
		{"regex no args", builtinRegex, nil},
		{"base64Decode no args", builtinBase64Decode, nil},
		{"base64Encode no args", builtinBase64Encode, nil},
		{"duration no args", builtinDuration, nil},
		{"parseTime no args", builtinParseTime, nil},
		{"format no args", builtinFormat, nil},
		{"typeOf no args", builtinTypeOf, nil},
		{"isType no args", builtinIsType, nil},
		{"hasKey no args", builtinHasKey, nil},
		{"keys no args", builtinKeys, nil},
		{"values no args", builtinValues, nil},
		{"cidrContains no args", builtinCIDRContains, nil},
		{"cidrOverlap no args", builtinCIDROverlap, nil},
		{"ipVersion no args", builtinIPVersion, nil},
		{"unitsParse no args", builtinUnitsParse, nil},
		{"lookup no args", builtinLookup, nil},
		{"flatten no args", builtinFlatten, nil},
		{"unique no args", builtinUnique, nil},
		{"sort no args", builtinSort, nil},
		{"filter no args", builtinFilter, nil},
		{"semver no args", builtinSemverCompare, nil},
		{"jsonPath no args", builtinJSONPath, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(ctx, tt.args...)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// --- Helper functions ---

func TestToSlice(t *testing.T) {
	// []any
	s, ok := toSlice([]any{1, 2})
	if !ok || len(s) != 2 {
		t.Error("expected []any conversion")
	}

	// []string
	s, ok = toSlice([]string{"a", "b"})
	if !ok || len(s) != 2 {
		t.Error("expected []string conversion")
	}

	// []int
	s, ok = toSlice([]int{1, 2})
	if !ok || len(s) != 2 {
		t.Error("expected []int conversion")
	}

	// []float64
	s, ok = toSlice([]float64{1.0, 2.0})
	if !ok || len(s) != 2 {
		t.Error("expected []float64 conversion")
	}

	// unsupported
	_, ok = toSlice("not a slice")
	if ok {
		t.Error("expected false for string")
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		input any
		want  float64
	}{
		{float64(1.5), 1.5},
		{float32(1.5), 1.5},
		{int(42), 42.0},
		{int64(42), 42.0},
		{"3.14", 3.14},
	}
	for _, tt := range tests {
		result, err := toFloat64(tt.input)
		if err != nil {
			t.Errorf("toFloat64(%v) error: %v", tt.input, err)
			continue
		}
		if result != tt.want {
			t.Errorf("toFloat64(%v) = %v, want %v", tt.input, result, tt.want)
		}
	}

	// Error case
	_, err := toFloat64([]string{"not a number"})
	if err == nil {
		t.Error("expected error for non-numeric type")
	}
}

func TestIsIntegral(t *testing.T) {
	if !isIntegral(5.0) {
		t.Error("5.0 should be integral")
	}
	if isIntegral(5.5) {
		t.Error("5.5 should not be integral")
	}
}
