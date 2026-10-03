package engine

import (
	"fmt"
	"strings"
)

// A rule's message is a template, parsed at load:
//
//	{{.name}}        a binding: length, version, datetime, count, or a func bind
//	{{path}}         a field: an input path, or a forEach alias path such as
//	                 {{c.name}}; {{_index}} is the element's position
//
// A message that refers to a forEach alias is rendered once per failing
// element, so "container {{c.name}} ..." names each offending container. A
// placeholder that does not resolve is left as written.
type msgTemplate struct {
	parts     []msgPart
	hasBinds  bool
	hasFrames bool // refers to a forEach alias
}

type msgPart struct {
	text  string // literal text, or the placeholder as written
	bind  string // binding name, for {{.name}}
	path  *fieldPath
	alias bool // path starts with a forEach alias (or _index)
}

func parseMessage(msg string, aliases map[string]bool) (msgTemplate, error) {
	var t msgTemplate
	for msg != "" {
		open := strings.Index(msg, "{{")
		if open < 0 {
			t.parts = append(t.parts, msgPart{text: msg})
			break
		}
		end := strings.Index(msg[open:], "}}")
		if end < 0 {
			return t, fmt.Errorf("message: unterminated {{")
		}
		if open > 0 {
			t.parts = append(t.parts, msgPart{text: msg[:open]})
		}
		raw := msg[open : open+end+2]
		inner := strings.TrimSpace(raw[2 : len(raw)-2])
		part := msgPart{text: raw}
		if name, ok := strings.CutPrefix(inner, "."); ok {
			part.bind = name
			t.hasBinds = true
		} else {
			p, err := parsePath(inner)
			if err != nil {
				return t, fmt.Errorf("message: %w", err)
			}
			part.path = &p
			first := p.segs[0].key
			part.alias = !p.segs[0].isIdx && !p.segs[0].isAll && (aliases[first] || first == "_index")
			t.hasFrames = t.hasFrames || part.alias
		}
		t.parts = append(t.parts, part)
		msg = msg[open+end+2:]
	}
	return t, nil
}

// render fills the template. frames are the forEach elements of one failure,
// outermost first; an alias resolves to the innermost frame with its name.
func (t msgTemplate) render(root map[string]any, binds map[string]any, frames []frame) string {
	var b strings.Builder
	for _, p := range t.parts {
		var v any
		var ok bool
		switch {
		case p.bind != "":
			v, ok = binds[p.bind]
		case p.path == nil:
			b.WriteString(p.text)
			continue
		case p.alias:
			v, ok = resolveInFrames(*p.path, frames)
		default:
			v, ok = p.path.walk(root, p.path.segs)
		}
		if ok {
			b.WriteString(render(v))
		} else {
			b.WriteString(p.text)
		}
	}
	return b.String()
}

func resolveInFrames(p fieldPath, frames []frame) (any, bool) {
	first := p.segs[0].key
	for i := len(frames) - 1; i >= 0; i-- {
		switch {
		case first == "_index" && len(p.segs) == 1:
			return frames[i].index, true
		case frames[i].name == first:
			return p.walk(frames[i].item, p.segs[1:])
		}
	}
	return nil, false
}

// message renders a failing rule's message: once per failing forEach element
// when the template refers to an alias and such failures were recorded,
// otherwise once. Repeated renderings are dropped.
func (t msgTemplate) message(root map[string]any, binds map[string]any, failures [][]frame) string {
	if !t.hasFrames || len(failures) == 0 {
		return t.render(root, binds, nil)
	}
	seen := make(map[string]bool, len(failures))
	var out []string
	for _, f := range failures {
		if m := t.render(root, binds, f); !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return strings.Join(out, "; ")
}
