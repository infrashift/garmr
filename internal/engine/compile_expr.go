package engine

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// exprCompiler turns a schema-validated `expr` (decoded from the policy's
// JSON form: maps, lists, strings, float64s, bools) into a node tree. Every
// structural problem (no operator or several, a malformed path, an invalid
// regex, semver or datetime operand, an unknown builtin) is a load error here
// rather than a per-request failure.
type exprCompiler struct {
	builtins map[string]BuiltinFunc

	// aliases collects every forEach alias in the rule, so the rule's
	// message template can tell alias references from input paths.
	aliases map[string]bool
}

type field struct {
	name string
	v    any
}

// fieldsOf lists a struct's fields in name order, so messages that join
// per-operator results are deterministic.
func fieldsOf(v any) ([]field, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a struct")
	}
	out := make([]field, 0, len(m))
	for k, fv := range m {
		out = append(out, field{k, fv})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// get returns a struct field, or nil when v is not a struct or lacks it.
func get(v any, name string) any {
	m, _ := v.(map[string]any)
	return m[name]
}

const exprOperators = "all, any, not, match, compare, forEach, func"

func (c *exprCompiler) expr(v any, scope []string) (node, error) {
	fields, err := fieldsOf(v)
	if err != nil {
		return nil, fmt.Errorf("expression: %w", err)
	}
	// Exactly one operator per expression. Extra operators used to be
	// silently ignored after the first in dispatch order, so a rule that
	// declared two checks enforced one.
	if len(fields) != 1 {
		names := make([]string, len(fields))
		for i, f := range fields {
			names[i] = f.name
		}
		return nil, fmt.Errorf("an expression must set exactly one operator (%s), got %d: %v; combine checks with all/any", exprOperators, len(fields), names)
	}

	f := fields[0]
	switch f.name {
	case "all", "any":
		kids, err := c.exprList(f.v, scope)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		if f.name == "all" {
			return allNode(kids), nil
		}
		return anyNode(kids), nil
	case "not":
		kid, err := c.expr(f.v, scope)
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		return notNode{kid}, nil
	case "match":
		n, err := c.match(f.v, scope)
		if err != nil {
			return nil, fmt.Errorf("match: %w", err)
		}
		return n, nil
	case "compare":
		n, err := c.compare(f.v, scope)
		if err != nil {
			return nil, fmt.Errorf("compare: %w", err)
		}
		return n, nil
	case "forEach":
		n, err := c.forEach(f.v, scope)
		if err != nil {
			return nil, fmt.Errorf("forEach: %w", err)
		}
		return n, nil
	case "func":
		n, err := c.funcExpr(f.v, scope)
		if err != nil {
			return nil, fmt.Errorf("func: %w", err)
		}
		return n, nil
	}
	return nil, fmt.Errorf("unknown expression operator %q; valid operators are: %s", f.name, exprOperators)
}

func (c *exprCompiler) exprList(v any, scope []string) ([]node, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list of expressions")
	}
	var out []node
	for i, item := range list {
		n, err := c.expr(item, scope)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// path compiles a field path against the forEach aliases in scope. A path
// whose first segment names an alias reads that element; `_index` reads the
// innermost element's position; anything else reads the input.
func (c *exprCompiler) path(s string, scope []string) (pathSrc, error) {
	p, err := parsePath(s)
	if err != nil {
		return pathSrc{}, err
	}
	first := p.segs[0]
	if !first.isIdx && !first.isAll {
		if first.key == "_index" && len(scope) > 0 {
			if len(p.segs) > 1 {
				return pathSrc{}, fmt.Errorf("path %q: _index is a number and has no fields", s)
			}
			return pathSrc{p: p, frame: len(scope) - 1, isIndex: true}, nil
		}
		for i := len(scope) - 1; i >= 0; i-- {
			if scope[i] == first.key {
				return pathSrc{p: p, frame: i}, nil
			}
		}
	}
	return pathSrc{p: p, frame: -1}, nil
}

func str(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", what)
	}
	return s, nil
}

func integer(v any) (int64, error) {
	f, ok := asNumber(v)
	if !ok || f != math.Trunc(f) {
		return 0, fmt.Errorf("must be an integer")
	}
	return int64(f), nil
}

// --- #Value ----------------------------------------------------------------

func (c *exprCompiler) value(v any, scope []string) (valueSrc, error) {
	fields, err := fieldsOf(v)
	if err != nil {
		return nil, fmt.Errorf("value: %w", err)
	}
	if len(fields) != 1 {
		return nil, fmt.Errorf("a value must set exactly one of 'path', 'literal', or 'func', got %d", len(fields))
	}
	f := fields[0]
	switch f.name {
	case "literal":
		return litSrc{f.v}, nil
	case "path":
		s, err := str(f.v, "path")
		if err != nil {
			return nil, err
		}
		return c.path(s, scope)
	case "func":
		return c.call(f.v, scope)
	}
	// `env` in particular: reading the server's environment would let any
	// policy author exfiltrate it through violation messages.
	return nil, fmt.Errorf("value source %q is not supported; a value must set exactly one of 'path', 'literal', or 'func'", f.name)
}

func (c *exprCompiler) call(v any, scope []string) (funcSrc, error) {
	name, err := str(get(v, "name"), "func name")
	if err != nil {
		return funcSrc{}, err
	}
	fn, ok := c.builtins[name]
	if !ok {
		return funcSrc{}, fmt.Errorf("unknown builtin %q", name)
	}
	src := funcSrc{name: name, fn: fn}
	if args := get(v, "args"); args != nil {
		list, ok := args.([]any)
		if !ok {
			return funcSrc{}, fmt.Errorf("func %s: args must be a list", name)
		}
		for i, item := range list {
			arg, err := c.value(item, scope)
			if err != nil {
				return funcSrc{}, fmt.Errorf("func %s: args[%d]: %w", name, i, err)
			}
			src.args = append(src.args, arg)
		}
	}
	return src, nil
}

func (c *exprCompiler) funcExpr(v any, scope []string) (node, error) {
	call, err := c.call(v, scope)
	if err != nil {
		return nil, err
	}
	n := funcNode{call: call}
	n.expect, n.hasExpect = v.(map[string]any)["expect"]
	if bv := get(v, "bind"); bv != nil {
		if n.bindAs, err = str(bv, "bind"); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// --- forEach ---------------------------------------------------------------

var identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

func (c *exprCompiler) forEach(v any, scope []string) (node, error) {
	n := forEachNode{allowEmpty: true}
	fields, err := fieldsOf(v)
	if err != nil {
		return nil, err
	}
	ps, err := str(get(v, "path"), "path")
	if err != nil {
		return nil, err
	}
	if n.src, err = c.path(ps, scope); err != nil {
		return nil, err
	}
	alias := "item"
	var cond, where any
	hasMode, hasAllowEmpty := false, false
	for _, f := range fields {
		switch f.name {
		case "path":
		case "as":
			if alias, err = str(f.v, "as"); err != nil {
				return nil, err
			}
		case "condition":
			cond = f.v
		case "where":
			where = f.v
		case "mode":
			mode, merr := str(f.v, "mode")
			if merr != nil || (mode != "all" && mode != "any") {
				return nil, fmt.Errorf("mode must be \"all\" or \"any\"")
			}
			n.anyMode = mode == "any"
			hasMode = true
		case "allowEmpty":
			var ok bool
			if n.allowEmpty, ok = f.v.(bool); !ok {
				return nil, fmt.Errorf("allowEmpty must be a boolean")
			}
			hasAllowEmpty = true
		case "count":
			if n.count, err = intChecks(f.v, "count", "'%s': %d elements matched, expected %s %d", n.src.p.raw); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown field %q", f.name)
		}
	}
	if cond == nil {
		return nil, fmt.Errorf("requires 'condition'")
	}
	if !identRe.MatchString(alias) {
		return nil, fmt.Errorf("'as' must be an identifier (letters, digits, underscores), got %q", alias)
	}
	if n.count != nil && (hasMode || hasAllowEmpty) {
		return nil, fmt.Errorf("'count' replaces 'mode' and 'allowEmpty'; set one or the other")
	}
	n.alias = alias
	if c.aliases != nil {
		c.aliases[alias] = true
	}
	inner := append(append([]string(nil), scope...), alias)
	if n.cond, err = c.expr(cond, inner); err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}
	if where != nil {
		if n.where, err = c.expr(where, inner); err != nil {
			return nil, fmt.Errorf("where: %w", err)
		}
	}
	return n, nil
}

// --- compare ---------------------------------------------------------------

func (c *exprCompiler) compare(v any, scope []string) (node, error) {
	var n compareNode
	var err error
	if n.left, err = c.value(get(v, "left"), scope); err != nil {
		return nil, fmt.Errorf("left: %w", err)
	}
	if n.right, err = c.value(get(v, "right"), scope); err != nil {
		return nil, fmt.Errorf("right: %w", err)
	}
	if n.op, err = str(get(v, "op"), "op"); err != nil {
		return nil, err
	}
	if n.fn, err = compileCompareOp(n.op, n.right); err != nil {
		return nil, err
	}
	return n, nil
}

// ordering is a comparison operator over a three-way comparison result.
// Numbers, lengths, semvers, datetimes and compare all share these.
type ordering struct {
	symbol string
	ok     func(cmp int) bool
}

var orderings = map[string]ordering{
	"equals":             {"==", func(c int) bool { return c == 0 }},
	"greaterThan":        {">", func(c int) bool { return c > 0 }},
	"greaterThanOrEqual": {">=", func(c int) bool { return c >= 0 }},
	"lessThan":           {"<", func(c int) bool { return c < 0 }},
	"lessThanOrEqual":    {"<=", func(c int) bool { return c <= 0 }},
}

// compareOrderings maps compare's ordering operators onto orderings, and
// names the kind of operand each needs ("" for two numbers or two strings).
var compareOrderings = map[string]struct{ ordering, kind string }{
	"<": {"lessThan", ""}, "<=": {"lessThanOrEqual", ""}, ">": {"greaterThan", ""}, ">=": {"greaterThanOrEqual", ""},
	"semverEq": {"equals", "semver"}, "semverGt": {"greaterThan", "semver"}, "semverGte": {"greaterThanOrEqual", "semver"},
	"semverLt": {"lessThan", "semver"}, "semverLte": {"lessThanOrEqual", "semver"},
	"after": {"greaterThan", "datetime"}, "afterOrEqual": {"greaterThanOrEqual", "datetime"},
	"before": {"lessThan", "datetime"}, "beforeOrEqual": {"lessThanOrEqual", "datetime"},
}

func compileCompareOp(op string, right valueSrc) (compareFn, error) {
	if co, ok := compareOrderings[op]; ok {
		want := orderings[co.ordering].ok
		switch co.kind {
		case "semver":
			return parsedOrder(op, co.kind, compareSemver, want), nil
		case "datetime":
			return parsedOrder(op, co.kind, compareDatetime, want), nil
		}
		return func(_ *evalCtx, l, r any) (bool, error) {
			cmp, ok := orderValues(l, r)
			if !ok {
				return false, fmt.Errorf("non-numeric operand: %q needs two numbers or two strings, got %s and %s", op, valueKind(l), valueKind(r))
			}
			return want(cmp), nil
		}, nil
	}

	strs := func(f func(l, r string) bool) compareFn {
		return func(_ *evalCtx, l, r any) (bool, error) {
			ls, lok := l.(string)
			rs, rok := r.(string)
			if !lok || !rok {
				return false, fmt.Errorf("%q needs two strings, got %s and %s", op, valueKind(l), valueKind(r))
			}
			return f(ls, rs), nil
		}
	}

	switch op {
	case "==", "!=":
		want := op == "=="
		return func(_ *evalCtx, l, r any) (bool, error) { return eqValues(l, r) == want, nil }, nil
	case "in", "notIn":
		want := op == "in"
		return func(_ *evalCtx, l, r any) (bool, error) {
			list, ok := r.([]any)
			if !ok {
				// notIn against a non-list used to pass: a missing right-hand
				// path made every value "not in" it.
				return false, fmt.Errorf("%q needs a list on the right, got %s", op, valueKind(r))
			}
			for _, e := range list {
				if eqValues(l, e) {
					return want, nil
				}
			}
			return !want, nil
		}, nil
	case "contains":
		// A list contains an element; a string contains a substring.
		return func(ec *evalCtx, l, r any) (bool, error) {
			if list, ok := l.([]any); ok {
				for _, e := range list {
					if eqValues(e, r) {
						return true, nil
					}
				}
				return false, nil
			}
			return strs(strings.Contains)(ec, l, r)
		}, nil
	case "subsetOf":
		return subsetOf, nil
	case "hasPrefix":
		return strs(strings.HasPrefix), nil
	case "hasSuffix":
		return strs(strings.HasSuffix), nil
	case "matches":
		// A literal pattern is compiled once, here; one from the input goes
		// through the bounded shared cache.
		if lit, ok := right.(litSrc); ok {
			pattern, isStr := lit.v.(string)
			if !isStr {
				return nil, fmt.Errorf("\"matches\" needs a string pattern")
			}
			re, err := compileRegex(pattern)
			if err != nil {
				return nil, err
			}
			return strs(func(l, _ string) bool { return re.MatchString(l) }), nil
		}
		return func(_ *evalCtx, l, r any) (bool, error) {
			ls, lok := l.(string)
			rs, rok := r.(string)
			if !lok || !rok {
				return false, fmt.Errorf("\"matches\" needs two strings, got %s and %s", valueKind(l), valueKind(r))
			}
			re, err := sharedRegexCache.get(rs)
			if err != nil {
				return false, fmt.Errorf("invalid pattern %q: %w", rs, err)
			}
			return re.MatchString(ls), nil
		}, nil
	}
	return nil, fmt.Errorf("unknown comparison operator %q", op)
}

// subsetOf reports whether left is contained in right: every key of a left
// object present in the right object with an equal value (a label selector
// within labels), or every element of a left list present in the right list.
func subsetOf(_ *evalCtx, l, r any) (bool, error) {
	switch lv := l.(type) {
	case map[string]any:
		rv, ok := r.(map[string]any)
		if !ok {
			break
		}
		for k, x := range lv {
			if y, present := rv[k]; !present || !eqValues(x, y) {
				return false, nil
			}
		}
		return true, nil
	case []any:
		rv, ok := r.([]any)
		if !ok {
			break
		}
		have := make(map[string]struct{}, len(rv))
		for _, y := range rv {
			have[setKey(y)] = struct{}{}
		}
		for _, x := range lv {
			if _, present := have[setKey(x)]; !present {
				return false, nil
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("\"subsetOf\" needs two objects or two lists, got %s and %s", valueKind(l), valueKind(r))
}

// parsedOrder builds a compare operator over two strings parsed by cmp
// (semver or datetime). Unparseable operands are errors, never "equal".
func parsedOrder(op, what string, cmp func(a, b string) (int, error), want func(int) bool) compareFn {
	return func(_ *evalCtx, l, r any) (bool, error) {
		ls, lok := l.(string)
		rs, rok := r.(string)
		if !lok || !rok {
			return false, fmt.Errorf("invalid %s operand: %q needs two strings, got %s and %s", what, op, valueKind(l), valueKind(r))
		}
		c, err := cmp(ls, rs)
		if err != nil {
			return false, fmt.Errorf("invalid %s operand: %w", what, err)
		}
		return want(c), nil
	}
}

// --- match -----------------------------------------------------------------

const matchOperators = "exists, equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, pattern, contains, hasPrefix, hasSuffix, in, notIn, unique, uniqueBy, sorted, containsAll, containsAny, subsetOf, length, semver, datetime"

func (c *exprCompiler) match(v any, scope []string) (node, error) {
	fields, err := fieldsOf(v)
	if err != nil {
		return nil, err
	}
	var n matchNode
	ps, err := str(get(v, "path"), "path")
	if err != nil {
		return nil, err
	}
	if n.src, err = c.path(ps, scope); err != nil {
		return nil, err
	}
	ops := 0
	for _, f := range fields {
		if f.name == "path" {
			continue
		}
		ops++
		if f.name == "exists" {
			b, ok := f.v.(bool)
			if !ok {
				return nil, fmt.Errorf("exists must be a boolean")
			}
			n.exists = &b
			continue
		}
		chk, err := c.matchOp(f.name, f.v, n.src.p.raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		n.checks = append(n.checks, chk)
	}
	if ops == 0 {
		return nil, fmt.Errorf("requires one of: %s", matchOperators)
	}
	return n, nil
}

// matchOp compiles one operator. path is used only in messages.
func (c *exprCompiler) matchOp(name string, v any, path string) (check, error) {
	switch name {
	case "equals":
		want := v
		return func(_ *evalCtx, got any) result {
			if !eqValues(got, want) {
				return failf("'%s' expected '%v', got '%v'", path, want, got)
			}
			return result{}
		}, nil

	case "greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual":
		want, ok := asNumber(v)
		if !ok {
			return nil, fmt.Errorf("operand must be a number")
		}
		o := orderings[name]
		return func(_ *evalCtx, got any) result {
			f, ok := asNumber(got)
			if !ok {
				return errorf("'%s' is not numeric (got %s)", path, valueKind(got))
			}
			if cmp, _ := orderValues(f, want); !o.ok(cmp) {
				return failf("'%s' expected %s %v, got %v", path, o.symbol, want, f)
			}
			return result{}
		}, nil

	case "pattern":
		s, err := str(v, "pattern")
		if err != nil {
			return nil, err
		}
		re, err := compileRegex(s)
		if err != nil {
			return nil, err
		}
		return stringCheck(path, func(got string) result {
			if !re.MatchString(got) {
				return failf("'%s' does not match pattern '%s'", got, s)
			}
			return result{}
		}), nil

	case "contains", "hasPrefix", "hasSuffix":
		s, err := str(v, name)
		if err != nil {
			return nil, err
		}
		test, verb := strings.Contains, "contain"
		if name == "hasPrefix" {
			test, verb = strings.HasPrefix, "have prefix"
		} else if name == "hasSuffix" {
			test, verb = strings.HasSuffix, "have suffix"
		}
		return stringCheck(path, func(got string) result {
			if !test(got, s) {
				return failf("'%s' does not %s '%s'", path, verb, s)
			}
			return result{}
		}), nil

	case "in", "notIn":
		set, display, err := literalSet(v)
		if err != nil {
			return nil, err
		}
		if name == "in" {
			return func(_ *evalCtx, got any) result {
				if _, ok := set[setKey(got)]; !ok {
					return failf("'%s' value '%v' not in allowed list %v", path, got, display)
				}
				return result{}
			}, nil
		}
		return func(_ *evalCtx, got any) result {
			if _, ok := set[setKey(got)]; ok {
				return failf("'%s' value '%v' is in forbidden list", path, got)
			}
			return result{}
		}, nil

	case "containsAll", "containsAny", "subsetOf":
		set, display, err := literalSet(v)
		if err != nil {
			return nil, err
		}
		want := v.([]any)
		return listCheck(path, func(items []any) result {
			switch name {
			case "subsetOf":
				for _, it := range items {
					if _, ok := set[setKey(it)]; !ok {
						return failf("'%s' contains value %v not in the allowed set", path, it)
					}
				}
				return result{}
			}
			present := make(map[string]struct{}, len(items))
			for _, it := range items {
				present[setKey(it)] = struct{}{}
			}
			var missing []string
			for _, w := range want {
				if _, ok := present[setKey(w)]; ok {
					if name == "containsAny" {
						return result{}
					}
				} else {
					missing = append(missing, render(w))
				}
			}
			if name == "containsAny" {
				return failf("'%s' contains none of %v", path, display)
			}
			if len(missing) > 0 {
				return failf("'%s' is missing required values: %v", path, missing)
			}
			return result{}
		}), nil

	case "unique":
		required, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("must be a boolean")
		}
		return listCheck(path, func(items []any) result {
			if !required {
				return result{}
			}
			seen := make(map[string]struct{}, len(items))
			for _, it := range items {
				k := setKey(it)
				if _, dup := seen[k]; dup {
					return failf("'%s' contains duplicate value %v", path, it)
				}
				seen[k] = struct{}{}
			}
			return result{}
		}), nil

	case "uniqueBy":
		s, err := str(v, "uniqueBy")
		if err != nil {
			return nil, err
		}
		key, err := parsePath(s)
		if err != nil {
			return nil, err
		}
		return listCheck(path, func(items []any) result {
			seen := make(map[string]struct{}, len(items))
			for i, it := range items {
				kv, ok := key.walk(it, key.segs)
				if !ok {
					return failf("'%s[%d]' has no field '%s'", path, i, s)
				}
				k := setKey(kv)
				if _, dup := seen[k]; dup {
					return failf("'%s' contains duplicate %s %v", path, s, kv)
				}
				seen[k] = struct{}{}
			}
			return result{}
		}), nil

	case "sorted":
		order, err := str(v, "sorted")
		if err != nil || (order != "asc" && order != "desc") {
			return nil, fmt.Errorf("must be \"asc\" or \"desc\"")
		}
		return listCheck(path, func(items []any) result {
			for i := 1; i < len(items); i++ {
				cmp, ok := orderValues(items[i-1], items[i])
				if !ok {
					return errorf("'%s' contains values that cannot be ordered", path)
				}
				if (order == "asc" && cmp > 0) || (order == "desc" && cmp < 0) {
					return failf("'%s' is not sorted in %sending order at index %d", path, order, i)
				}
			}
			return result{}
		}), nil

	case "length":
		return c.lengthOp(v, path)
	case "semver":
		return c.semverOp(v, path)
	case "datetime":
		return c.datetimeOp(v, path)
	}
	return nil, fmt.Errorf("unknown match operator; valid operators are: %s", matchOperators)
}

func stringCheck(path string, f func(string) result) check {
	return func(_ *evalCtx, got any) result {
		s, ok := got.(string)
		if !ok {
			return errorf("path '%s' is not a string", path)
		}
		return f(s)
	}
}

func listCheck(path string, f func([]any) result) check {
	return func(_ *evalCtx, got any) result {
		items, ok := got.([]any)
		if !ok {
			return errorf("path '%s' is not an array", path)
		}
		return f(items)
	}
}

// literalSet decodes a list operand into a hash set plus a display form.
func literalSet(v any) (map[string]struct{}, []string, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("must be a list")
	}
	set := make(map[string]struct{}, len(items))
	display := make([]string, len(items))
	for i, it := range items {
		set[setKey(it)] = struct{}{}
		display[i] = render(it)
	}
	return set, display, nil
}

// subChecks compiles the operators of a length/semver/datetime block. Each
// specified operator must hold (AND), and an empty block is an error.
func subChecks(v any, family, valid string, build func(name string, op any) (func(any) result, error)) ([]func(any) result, error) {
	fields, err := fieldsOf(v)
	if err != nil {
		return nil, err
	}
	var out []func(any) result
	for _, f := range fields {
		chk, err := build(f.name, f.v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		if chk == nil {
			return nil, fmt.Errorf("unknown %s operator %q; valid operators are: %s", family, f.name, valid)
		}
		out = append(out, chk)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s requires one of: %s", family, valid)
	}
	return out, nil
}

// andChecks runs prepared sub-checks against one value, joining failures.
func andChecks(subs []func(any) result, v any) result {
	var msgs []string
	out := pass
	for _, s := range subs {
		r := s(v)
		if r.out == pass {
			continue
		}
		msgs = append(msgs, r.msg)
		if r.out == fail || out == pass {
			out = r.out
		}
	}
	if out == pass {
		return result{}
	}
	return result{out, strings.Join(msgs, "; ")}
}

// intChecks compiles an integer comparison block (length, forEach count):
// each operator of the block must hold. format renders a failure from the
// path, the actual number, the operator symbol and the operand.
func intChecks(v any, family, format, path string) ([]func(any) result, error) {
	const valid = "equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual"
	return subChecks(v, family, valid, func(name string, op any) (func(any) result, error) {
		o, known := orderings[name]
		if !known {
			return nil, nil
		}
		want, err := integer(op)
		if err != nil {
			return nil, err
		}
		return func(got any) result {
			if n := int64(got.(int)); !o.ok(cmpInt(n, want)) {
				return failf(format, path, n, o.symbol, want)
			}
			return result{}
		}, nil
	})
}

func (c *exprCompiler) lengthOp(v any, path string) (check, error) {
	subs, err := intChecks(v, "length", "'%s' length is %d, expected %s %d", path)
	if err != nil {
		return nil, err
	}
	return func(ec *evalCtx, got any) result {
		var n int
		switch x := got.(type) {
		case []any:
			n = len(x)
		case string:
			n = utf8.RuneCountInString(x)
		default:
			return errorf("'%s' is not an array or string", path)
		}
		ec.bind("length", n)
		return andChecks(subs, n)
	}, nil
}

func (c *exprCompiler) semverOp(v any, path string) (check, error) {
	const valid = "equals, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual, constraint"
	subs, err := subChecks(v, "semver", valid, func(name string, op any) (func(any) result, error) {
		s, err := str(op, name)
		if err != nil {
			return nil, err
		}
		if name == "constraint" {
			conds, cerr := parseSemverConstraint(s)
			if cerr != nil {
				return nil, fmt.Errorf("invalid semver constraint %q: %w", s, cerr)
			}
			return func(got any) result {
				ver := got.(semverParts)
				if !conds.match(ver) {
					return failf("'%s' version %s does not satisfy constraint %s", path, ver.raw, s)
				}
				return result{}
			}, nil
		}
		o, known := orderings[name]
		if !known {
			return nil, nil
		}
		want, err := parseSemver(s)
		if err != nil {
			return nil, fmt.Errorf("invalid semver %q", s)
		}
		return func(got any) result {
			ver := got.(semverParts)
			if !o.ok(compareSemverParsed(ver, want)) {
				return failf("'%s' version %s is not %s %s", path, ver.raw, o.symbol, s)
			}
			return result{}
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return func(ec *evalCtx, got any) result {
		s, ok := got.(string)
		if !ok {
			return errorf("'%s' is not a string", path)
		}
		ver, err := parseSemver(s)
		if err != nil {
			return errorf("'%s' is not a valid semver: %s", path, s)
		}
		ec.bind("version", s)
		return andChecks(subs, ver)
	}, nil
}

func (c *exprCompiler) datetimeOp(v any, path string) (check, error) {
	const valid = "after, before, afterOrEqual, beforeOrEqual, withinDays, withinHours, expiresAfterDays, notExpired"
	subs, err := subChecks(v, "datetime", valid, func(name string, op any) (func(any) result, error) {
		switch name {
		case "after", "before", "afterOrEqual", "beforeOrEqual":
			s, err := str(op, name)
			if err != nil {
				return nil, err
			}
			// "now" is resolved per evaluation; anything else once, here.
			at := func() time.Time { return time.Now() }
			if !strings.EqualFold(s, "now") {
				t, err := parseDateTime(s)
				if err != nil {
					return nil, fmt.Errorf("invalid datetime %q", s)
				}
				at = func() time.Time { return t }
			}
			o := orderings[compareOrderings[name].ordering]
			verb := map[string]string{"after": "is not after", "before": "is not before", "afterOrEqual": "is before", "beforeOrEqual": "is after"}[name]
			return func(got any) result {
				d := got.(datetimeArg)
				if !o.ok(d.t.Compare(at())) {
					return failf("'%s' %s %s %s", path, d.raw, verb, s)
				}
				return result{}
			}, nil

		case "withinDays", "withinHours", "expiresAfterDays":
			n, err := integer(op)
			if err != nil {
				return nil, err
			}
			unit, span := "days", time.Duration(n)*24*time.Hour
			if name == "withinHours" {
				unit, span = "hours", time.Duration(n)*time.Hour
			}
			if name == "expiresAfterDays" {
				return func(got any) result {
					d := got.(datetimeArg)
					if d.t.Before(time.Now().Add(span)) {
						return failf("'%s' %s expires in less than %d days", path, d.raw, n)
					}
					return result{}
				}, nil
			}
			// Within N units of now, in either direction. Only the future
			// bound used to be checked, so any past timestamp passed.
			return func(got any) result {
				d := got.(datetimeArg)
				if diff := time.Until(d.t); diff > span || diff < -span {
					return failf("'%s' %s is more than %d %s from now", path, d.raw, n, unit)
				}
				return result{}
			}, nil

		case "notExpired":
			want, ok := op.(bool)
			if !ok {
				return nil, fmt.Errorf("must be a boolean")
			}
			return func(got any) result {
				d := got.(datetimeArg)
				expired := d.t.Before(time.Now())
				if want && expired {
					return failf("'%s' %s has expired", path, d.raw)
				}
				if !want && !expired {
					return failf("'%s' %s has not expired", path, d.raw)
				}
				return result{}
			}, nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return func(ec *evalCtx, got any) result {
		s, ok := got.(string)
		if !ok {
			return errorf("'%s' is not a string", path)
		}
		t, err := parseDateTime(s)
		if err != nil {
			return errorf("'%s' is not a valid datetime: %s", path, s)
		}
		ec.bind("datetime", t.Format(time.RFC3339))
		return andChecks(subs, datetimeArg{t, s})
	}, nil
}

type datetimeArg struct {
	t   time.Time
	raw string
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compileRegex compiles a policy-authored pattern, applying the same length
// cap as patterns that arrive at request time.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("pattern too long: %d bytes (limit %d)", len(pattern), maxRegexPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	return re, nil
}
