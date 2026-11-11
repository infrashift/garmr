package engine

import (
	"encoding/json"
	"fmt"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cueerrors "cuelang.org/go/cue/errors"
	"cuelang.org/go/cue/format"
)

// A policy may declare the input it expects as a CUE definition:
//
//	spec: inputSchema: report.#ReviewReport
//
// The schema is used in two places, both outside the server's evaluation
// path, which stays CUE-free:
//
//   - At load, every input path the rules read is checked against it, so a
//     misspelled field (`risk_scor`) is a load error instead of a rule that
//     can never pass. This runs wherever policies load: server startup and
//     reload, `garmr validate`, /v1/validate.
//   - Callers that opt in (EvaluateOptions.CheckInputSchema: `garmr eval
//     --local` and `garmr test`) validate the input against it before any
//     rule runs, and get ErrInvalidInput when it does not conform.

// recordedPath is an input path a rule reads, as written and resolved to
// the input root: an alias path `f.file` inside a forEach over `findings`
// becomes findings[*].file.
type recordedPath struct {
	raw  string
	segs []pathSeg
}

// schemaPathChecker checks input paths against a policy's inputSchema.
type schemaPathChecker struct {
	schema cue.Value
}

// check reports a path the schema cannot satisfy. It only reports what the
// schema definitely rules out: a field a closed struct does not allow, or a
// path stepping into a value that is not a struct or list. Wherever the
// schema leaves the shape open (`_`, `{...}`, an unresolvable disjunction)
// the rest of the path is accepted.
func (c schemaPathChecker) check(p recordedPath) error {
	v := c.schema
	for i, seg := range p.segs {
		kind := v.IncompleteKind()
		if kind == cue.TopKind {
			return nil
		}
		at := describeSegs(p.segs[:i])
		if seg.isIdx || seg.isAll {
			if kind&cue.ListKind == 0 {
				return fmt.Errorf("path %q: %s is %s in spec.inputSchema, not a list", p.raw, at, kind)
			}
			elem := v.LookupPath(cue.MakePath(cue.AnyIndex))
			if !elem.Exists() && seg.isIdx {
				elem = v.LookupPath(cue.MakePath(cue.Index(seg.index)))
			}
			if !elem.Exists() {
				return nil
			}
			v = elem
			continue
		}
		if kind&cue.StructKind == 0 {
			return fmt.Errorf("path %q: %s is %s in spec.inputSchema, so it has no field %q", p.raw, at, kind, seg.key)
		}
		if !v.Allows(cue.Str(seg.key)) {
			return fmt.Errorf("path %q: spec.inputSchema does not allow field %q in %s", p.raw, seg.key, at)
		}
		next := lookupField(v, seg.key)
		if !next.Exists() {
			return nil
		}
		v = next
	}
	return nil
}

// lookupField finds a field's schema whether it is regular, optional or
// only matched by a pattern constraint ([string]: T).
func lookupField(v cue.Value, key string) cue.Value {
	sel := cue.Str(key)
	if f := v.LookupPath(cue.MakePath(sel)); f.Exists() {
		return f
	}
	if f := v.LookupPath(cue.MakePath(sel.Optional())); f.Exists() {
		return f
	}
	return v.LookupPath(cue.MakePath(cue.AnyString))
}

// describeSegs names a path prefix for error messages.
func describeSegs(segs []pathSeg) string {
	if len(segs) == 0 {
		return "the input"
	}
	var b strings.Builder
	for _, s := range segs {
		switch {
		case s.isAll:
			b.WriteString("[*]")
		case s.isIdx:
			fmt.Fprintf(&b, "[%d]", s.index)
		default:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(s.key)
		}
	}
	return "'" + b.String() + "'"
}

// inputSchemaSource renders a schema to self-contained CUE source, with
// imports inlined and closedness kept, so it can be compiled again after
// the load's CUE context is gone.
func inputSchemaSource(schema cue.Value) (string, error) {
	node := schema.Syntax(cue.Definitions(true), cue.InlineImports(true), cue.Docs(false),
		cue.Optional(true), cue.Patterns(true), cue.Attributes(false))
	b, err := format.Node(node)
	if err != nil {
		return "", err
	}
	// Prove now that it compiles on its own; a schema that only works in
	// its original package would otherwise fail on every checked request.
	if v := cuecontext.New().CompileBytes(b); v.Err() != nil {
		return "", fmt.Errorf("inputSchema is not self-contained: %w", v.Err())
	}
	return string(b), nil
}

// maxInputSchemaErrors bounds the violations listed in one error.
const maxInputSchemaErrors = 10

// checkInputSchema validates input against a policy's schema source. The
// input goes through JSON so numbers keep their JSON kinds: 3 is an int,
// 3.5 a float. (Encoding the decoded float64 directly would make every
// whole number a float and fail `int` fields.)
func checkInputSchema(policy *CompiledPolicy, input map[string]any) error {
	ctx := cuecontext.New()
	schema := ctx.CompileString(policy.inputSchema)
	if schema.Err() != nil {
		return fmt.Errorf("policy %s: compiling inputSchema: %w", policy.key(), schema.Err())
	}
	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("%w: encoding input: %w", ErrInvalidInput, err)
	}
	doc := ctx.CompileBytes(data)
	if doc.Err() != nil {
		return fmt.Errorf("%w: input is not valid JSON for CUE: %w", ErrInvalidInput, doc.Err())
	}
	err = schema.Unify(doc).Validate(cue.Concrete(true), cue.All())
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: input does not satisfy spec.inputSchema of policy %s: %s",
		ErrInvalidInput, policy.key(), formatSchemaErrors(err))
}

// formatSchemaErrors lists CUE validation errors by input path, without the
// synthetic prefix the rendered schema carries.
func formatSchemaErrors(err error) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range cueerrors.Errors(err) {
		var path []string
		for _, p := range e.Path() {
			if strings.HasPrefix(p, "_#") {
				continue
			}
			path = append(path, p)
		}
		format, args := e.Msg()
		msg := fmt.Sprintf(format, args...)
		if len(path) > 0 {
			msg = strings.Join(path, ".") + ": " + msg
		}
		if seen[msg] {
			continue
		}
		seen[msg] = true
		out = append(out, msg)
	}
	if len(out) > maxInputSchemaErrors {
		out = append(out[:maxInputSchemaErrors], fmt.Sprintf("and %d more", len(out)-maxInputSchemaErrors))
	}
	return strings.Join(out, "; ")
}
