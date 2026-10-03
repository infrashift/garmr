package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// A rule's expression is compiled once, at load, into a tree of nodes that
// evaluate directly against the request's JSON-shaped input. Nothing touches
// CUE at evaluation time, so evaluations share the compiled policy set freely
// and run fully in parallel.

// outcome is three-valued. An error (malformed input for an operator, a
// failing builtin, an expired deadline) is distinct from a plain failure so
// that `not` and `any` cannot turn it into a pass: `not` of an error is still
// an error, and an error fails the rule.
//
// A missing path is a plain failure, not an error, so
// `not: {match: {path: "x", equals: true}}` passes when x is absent.
type outcome uint8

const (
	pass outcome = iota
	fail
	errored
)

type result struct {
	out outcome
	msg string
}

func failf(format string, a ...any) result  { return result{fail, fmt.Sprintf(format, a...)} }
func errorf(format string, a ...any) result { return result{errored, fmt.Sprintf(format, a...)} }

// node is a compiled expression.
type node interface {
	eval(ec *evalCtx) result
}

type binding struct {
	name  string
	value any
}

// evalCtx carries the per-evaluation state through a rule's node tree.
type evalCtx struct {
	ctx  context.Context
	done <-chan struct{}
	root map[string]any

	// forEach frames, outermost first. Aliases are resolved to frame
	// positions at compile time; names are kept for message rendering.
	items []any
	index []int
	names []string

	// Bindings feed message templates; collected only for rules whose
	// message uses them.
	wantBinds bool
	binds     []binding

	// failures records the forEach frames of each failing element, for
	// rules whose message refers to a forEach alias. Collected only when
	// wantFrames is set; any subtree that ends up passing discards what it
	// recorded.
	wantFrames bool
	failures   [][]frame
}

// frame is one forEach element, as recorded for message rendering.
type frame struct {
	name  string
	item  any
	index int
}

// recordFailure snapshots the current frames, unless a deeper forEach
// already recorded the failure since mark.
func (ec *evalCtx) recordFailure(mark int) {
	if !ec.wantFrames || len(ec.failures) > mark {
		return
	}
	snap := make([]frame, len(ec.items))
	for i := range ec.items {
		snap[i] = frame{ec.names[i], ec.items[i], ec.index[i]}
	}
	ec.failures = append(ec.failures, snap)
}

func (ec *evalCtx) bind(name string, v any) {
	if ec.wantBinds {
		ec.binds = append(ec.binds, binding{name, v})
	}
}

// --- value sources ---------------------------------------------------------

// valueSrc produces an operand: a literal, an input path, or a builtin call.
type valueSrc interface {
	resolve(ec *evalCtx) (v any, found bool, err error)
}

type litSrc struct{ v any }

func (s litSrc) resolve(*evalCtx) (any, bool, error) { return s.v, true, nil }

// pathSrc reads the input, or a forEach element when the path's first
// segment is an in-scope alias (frame >= 0). isIndex reads the innermost
// element's position (`_index`).
type pathSrc struct {
	p       fieldPath
	frame   int
	isIndex bool
}

func (s pathSrc) resolve(ec *evalCtx) (any, bool, error) {
	switch {
	case s.isIndex:
		return ec.index[s.frame], true, nil
	case s.frame >= 0:
		v, ok := s.p.walk(ec.items[s.frame], s.p.segs[1:])
		return v, ok, nil
	}
	v, ok := s.p.walk(ec.root, s.p.segs)
	return v, ok, nil
}

type funcSrc struct {
	name string
	fn   BuiltinFunc
	args []valueSrc
}

func (s funcSrc) resolve(ec *evalCtx) (any, bool, error) {
	args := make([]any, len(s.args))
	for i, a := range s.args {
		// A missing path is passed as nil; the builtin decides what that means.
		v, _, err := a.resolve(ec)
		if err != nil {
			return nil, false, err
		}
		args[i] = v
	}
	v, err := s.fn(ec.ctx, args...)
	if err != nil {
		return nil, false, fmt.Errorf("builtin %s failed: %w", s.name, err)
	}
	return v, true, nil
}

// --- logical connectives ---------------------------------------------------

type allNode []node

// all fails on the first failing branch. An error only decides the outcome
// when no branch fails, so evaluation continues past one.
func (n allNode) eval(ec *evalCtx) result {
	var firstErr result
	for _, k := range n {
		r := k.eval(ec)
		switch r.out {
		case fail:
			return r
		case errored:
			if firstErr.out == pass {
				firstErr = r
			}
		}
	}
	return firstErr
}

type anyNode []node

// any passes on the first passing branch, keeping only that branch's
// bindings. On failure the last branch's message is reported.
func (n anyNode) eval(ec *evalCtx) result {
	mark, fmark := len(ec.binds), len(ec.failures)
	last := result{out: fail}
	var firstErr result
	for _, k := range n {
		r := k.eval(ec)
		if r.out == pass {
			ec.failures = ec.failures[:fmark]
			return r
		}
		ec.binds = ec.binds[:mark]
		if r.out == errored && firstErr.out == pass {
			firstErr = r
		}
		last = r
	}
	if firstErr.out != pass {
		return firstErr
	}
	return result{fail, last.msg}
}

type notNode struct{ n node }

func (n notNode) eval(ec *evalCtx) result {
	fmark := len(ec.failures)
	switch r := n.n.eval(ec); r.out {
	case pass:
		return result{out: fail}
	case fail:
		ec.failures = ec.failures[:fmark]
		return result{}
	default:
		return r
	}
}

// whenNode applies then only when the guard holds: a failing guard makes the
// rule not applicable, which passes. A guard that cannot be evaluated is an
// error — a check must never be skipped because its precondition broke.
type whenNode struct{ guard, then node }

func (n whenNode) eval(ec *evalCtx) result {
	fmark, bmark := len(ec.failures), len(ec.binds)
	switch r := n.guard.eval(ec); r.out {
	case fail:
		ec.failures, ec.binds = ec.failures[:fmark], ec.binds[:bmark]
		return result{}
	case errored:
		return result{errored, "when: " + r.msg}
	}
	return n.then.eval(ec)
}

// --- match -----------------------------------------------------------------

// check is one operator of a match (or length/semver/datetime) block.
type check func(ec *evalCtx, v any) result

// matchNode ANDs every operator specified on a path, reporting each unmet
// one. found is resolved once; only `exists` inspects absence itself.
type matchNode struct {
	src    pathSrc
	exists *bool
	checks []check
}

func (n matchNode) eval(ec *evalCtx) result {
	v, found, _ := n.src.resolve(ec)
	var msgs []string
	out := pass
	note := func(r result) {
		if r.out == pass {
			return
		}
		msgs = append(msgs, r.msg)
		if r.out == fail || out == pass {
			out = r.out
		}
	}

	if n.exists != nil {
		present := found && v != nil
		switch {
		case *n.exists && !present:
			note(failf("field '%s' does not exist", n.src.p))
		case !*n.exists && present:
			note(failf("field '%s' should not exist", n.src.p))
		}
	}
	if len(n.checks) > 0 {
		if !found {
			note(failf("path '%s' not found", n.src.p))
		} else {
			for _, c := range n.checks {
				note(c(ec, v))
			}
		}
	}

	if out == pass {
		return result{}
	}
	return result{out, strings.Join(msgs, "; ")}
}

// valueKind names a value's JSON kind for messages; strings are quoted so
// the offending value is visible.
func valueKind(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case nil:
		return "null"
	case bool:
		return "bool"
	case []any:
		return "list"
	case map[string]any:
		return "struct"
	}
	if _, ok := asNumber(v); ok {
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

// --- compare ---------------------------------------------------------------

// compareFn applies a compare operator. A false result is a failure; an
// error means the operands were not of a type the operator applies to.
type compareFn func(ec *evalCtx, left, right any) (bool, error)

type compareNode struct {
	left, right valueSrc
	op          string
	fn          compareFn
}

func (n compareNode) eval(ec *evalCtx) result {
	left, _, err := n.left.resolve(ec)
	if err != nil {
		return errorf("compare 'left': %v", err)
	}
	right, _, err := n.right.resolve(ec)
	if err != nil {
		return errorf("compare 'right': %v", err)
	}
	ok, err := n.fn(ec, left, right)
	if err != nil {
		return result{errored, err.Error()}
	}
	if !ok {
		return failf("comparison failed: %v %s %v", left, n.op, right)
	}
	return result{}
}

// --- func ------------------------------------------------------------------

type funcNode struct {
	call      funcSrc
	expect    any
	hasExpect bool
	bindAs    string
}

func (n funcNode) eval(ec *evalCtx) result {
	v, _, err := n.call.resolve(ec)
	if err != nil {
		return result{errored, err.Error()}
	}
	if n.bindAs != "" {
		ec.bind(n.bindAs, v)
	}
	if n.hasExpect {
		if !eqValues(v, n.expect) {
			return failf("builtin %s returned %v, expected %v", n.call.name, v, n.expect)
		}
		return result{}
	}
	// No expectation: a truthy result passes.
	if ok, reason := builtinResultTruthy(v); !ok {
		return failf("builtin %s %s", n.call.name, reason)
	}
	return result{}
}

// --- forEach ---------------------------------------------------------------

type forEachNode struct {
	src        pathSrc
	alias      string
	cond       node
	anyMode    bool
	allowEmpty bool

	// where, when set, selects the elements the condition applies to;
	// the others are skipped entirely (not checked, not counted).
	where node

	// count, when set, counts the elements that pass the condition and
	// checks the count instead of requiring all or any of them.
	count []func(any) result
}

func (n forEachNode) eval(ec *evalCtx) result {
	v, found, _ := n.src.resolve(ec)
	if !found {
		return failf("path '%s' not found", n.src.p)
	}
	list, ok := v.([]any)
	if !ok {
		return errorf("path '%s' is not an array", n.src.p)
	}
	if len(list) == 0 && n.count == nil {
		if !n.allowEmpty {
			return failf("path '%s' is an empty array", n.src.p)
		}
		return result{}
	}

	// Push a frame; the condition's alias paths were compiled to read it.
	ec.items = append(ec.items, nil)
	ec.index = append(ec.index, 0)
	ec.names = append(ec.names, n.alias)
	depth := len(ec.items) - 1
	defer func() {
		ec.items = ec.items[:depth]
		ec.index = ec.index[:depth]
		ec.names = ec.names[:depth]
	}()

	start := len(ec.failures)
	var failed []string
	var firstErr result
	matched, selected := 0, 0
	for i, item := range list {
		// The deadline is checked per element: a forEach over a large list
		// is the one construct whose cost is driven by the caller.
		select {
		case <-ec.done:
			return errorf("evaluation deadline exceeded in forEach over '%s'", n.src.p)
		default:
		}

		ec.items[depth], ec.index[depth] = item, i
		mark, bmark := len(ec.failures), len(ec.binds)
		if n.where != nil {
			w := n.where.eval(ec)
			ec.failures = ec.failures[:mark]
			if w.out == errored && firstErr.out == pass {
				firstErr = result{errored, fmt.Sprintf("%s[%d]: where: %s", n.src.p, i, w.msg)}
			}
			if w.out != pass {
				ec.binds = ec.binds[:bmark]
				continue
			}
		}
		selected++
		r := n.cond.eval(ec)
		switch {
		case r.out == pass:
			ec.failures = ec.failures[:mark]
			matched++
			if n.anyMode {
				ec.failures = ec.failures[:start]
				return result{}
			}
		case r.out == errored:
			if firstErr.out == pass {
				firstErr = result{errored, fmt.Sprintf("%s[%d]: %s", n.src.p, i, r.msg)}
			}
		case n.count == nil && !n.anyMode:
			failed = append(failed, fmt.Sprintf("%s[%d]: %s", n.src.p, i, r.msg))
			ec.recordFailure(mark)
		}
	}

	switch {
	case len(failed) > 0:
		return result{fail, strings.Join(failed, "; ")}
	case firstErr.out != pass:
		return firstErr
	case n.count != nil:
		// Elements that did not match are not failures of the rule.
		ec.failures = ec.failures[:start]
		ec.bind("count", matched)
		return andChecks(n.count, matched)
	case n.anyMode:
		ec.failures = ec.failures[:start]
		return failf("no items in '%s' matched the condition", n.src.p)
	case selected == 0 && !n.allowEmpty:
		return failf("no items in '%s' matched 'where'", n.src.p)
	}
	return result{}
}
