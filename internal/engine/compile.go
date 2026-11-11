package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/format"
	"go.uber.org/zap"
)

// canonicalPolicyHash renders a schema-unified policy value to canonical CUE
// syntax and hashes it. Identical policy content therefore produces the same
// hash regardless of file layout, load path, or CUE context — which is
// what lets `garmr policy digest` on a git checkout be compared with the
// digest a running server reports.
func canonicalPolicyHash(val cue.Value) (string, error) {
	node := val.Syntax(cue.Final(), cue.Docs(false), cue.Attributes(false))
	b, err := format.Node(node)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// newLoadContext returns a fresh CUE context and the schema's #Policy
// definition compiled in it. Each load operation uses its own context: the
// compiled policies keep no CUE values, so the context (and everything CUE
// allocated for the load) is released once the load finishes.
func newLoadContext() (*cue.Context, cue.Value, error) {
	ctx := cuecontext.New()
	schema := ctx.CompileString(policySchemaSource)
	if schema.Err() != nil {
		return nil, cue.Value{}, fmt.Errorf("compiling schema: %w", schema.Err())
	}
	return ctx, schema.LookupPath(cue.ParsePath("#Policy")), nil
}

// LoadPolicy loads and compiles a policy from CUE source, adding it to (or
// replacing it in) the loaded set.
//
// No production path calls this — the server loads exclusively from the
// policy directory. It is kept as the engine's in-memory load API: the test
// suites across cmd/garmr, internal/server and this package build their
// fixtures with it, and it validates against the same embedded schema as the
// directory loader.
func (e *Engine) LoadPolicy(ctx context.Context, name, namespace, source string) error {
	start := time.Now()

	// The reserved system namespace is used for synthetic results emitted by
	// the engine itself (e.g. no-policy-match). Reject any user policy that
	// would collide with it so that response consumers can distinguish real
	// policies from engine-generated ones by namespace alone.
	if namespace == ReservedSystemNamespace {
		e.observability().Metrics().RecordPolicyLoadError(name, namespace, "reserved_namespace")
		return fmt.Errorf("%w: namespace %q is reserved for internal use", ErrInvalidPolicy, namespace)
	}

	var compiled *CompiledPolicy
	err := e.mutate(false, func(cctx *cue.Context, schema cue.Value, pending map[string]*CompiledPolicy) error {
		var err error
		compiled, err = e.compilePolicySource(cctx, schema, name, namespace, source)
		if err != nil {
			return err
		}
		pending[policyKey(namespace, name)] = compiled
		return nil
	})
	if err != nil {
		e.observability().Metrics().RecordPolicyLoadError(name, namespace, "compilation")
		return err
	}

	e.logger.Info("policy loaded",
		zap.String("name", name),
		zap.String("namespace", namespace),
		zap.Int("rules", len(compiled.Rules)),
		zap.Duration("compile_time", time.Since(start)),
	)
	return nil
}

// compilePolicySource compiles and schema-validates a bare policy document.
func (e *Engine) compilePolicySource(cctx *cue.Context, schema cue.Value, name, namespace, source string) (*CompiledPolicy, error) {
	val := cctx.CompileString(source)
	if val.Err() != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, val.Err())
	}

	unified := val.Unify(schema)
	if unified.Err() != nil {
		return nil, fmt.Errorf("%w: schema validation failed: %w", ErrInvalidPolicy, unified.Err())
	}

	compiled, err := e.compilePolicy(unified, name, namespace)
	if err != nil {
		return nil, fmt.Errorf("compiling policy: %w", err)
	}
	return compiled, nil
}

// ruleDoc is one rule as decoded from the schema-unified JSON form.
type ruleDoc struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Priority    *int              `json:"priority"`
	Message     string            `json:"message"`
	Remediation string            `json:"remediation"`
	Category    string            `json:"category"`
	Tags        []string          `json:"tags"`
	When        any               `json:"when"`
	Expr        any               `json:"expr"`
	Details     map[string]string `json:"details"`
}

// specDoc is a policy's spec as decoded from its schema-unified JSON form.
// The schema has already validated every field, including defaults.
type specDoc struct {
	Target struct {
		Resources []ResourceSelector `json:"resources"`
	} `json:"target"`
	Rules       []ruleDoc       `json:"rules"`
	Enforcement EnforcementSpec `json:"enforcement"`
	Evaluation  struct {
		Order             EvaluationOrder `json:"order"`
		FailFast          bool            `json:"failFast"`
		IncludeCategories []string        `json:"includeCategories"`
		ExcludeCategories []string        `json:"excludeCategories"`
		IncludeTags       []string        `json:"includeTags"`
		ExcludeTags       []string        `json:"excludeTags"`
		MaxRules          int             `json:"maxRules"`
		Timeout           string          `json:"timeout"`
	} `json:"evaluation"`
}

// compilePolicy builds a CompiledPolicy from a schema-validated CUE value.
// This is the last use of CUE: everything is decoded into Go values and the
// rule expressions are compiled into evaluation trees.
func (e *Engine) compilePolicy(val cue.Value, name, namespace string) (*CompiledPolicy, error) {
	hash, err := canonicalPolicyHash(val)
	if err != nil {
		return nil, fmt.Errorf("hashing policy: %w", err)
	}
	specVal := val.LookupPath(cue.ParsePath("spec"))
	raw, err := marshalSpec(specVal)
	if err != nil {
		return nil, fmt.Errorf("decoding spec: %w", err)
	}
	var schema *schemaPathChecker
	if s := specVal.LookupPath(cue.ParsePath("inputSchema")); s.Exists() {
		schema = &schemaPathChecker{schema: s}
	}
	var spec specDoc
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("decoding spec: %w", err)
	}

	ev := spec.Evaluation
	cp := &CompiledPolicy{
		Name:        name,
		Namespace:   namespace,
		Hash:        hash,
		LoadedAt:    time.Now(),
		Target:      TargetSpec{Resources: spec.Target.Resources},
		Enforcement: spec.Enforcement,
		Evaluation: EvaluationConfig{
			Order:             ev.Order,
			FailFast:          ev.FailFast,
			IncludeCategories: ev.IncludeCategories,
			ExcludeCategories: ev.ExcludeCategories,
			IncludeTags:       ev.IncludeTags,
			ExcludeTags:       ev.ExcludeTags,
			MaxRules:          ev.MaxRules,
		},
	}
	if cp.Evaluation.Order == "" {
		cp.Evaluation.Order = EvalOrderPriority
	}
	if ev.Timeout != "" {
		d, err := time.ParseDuration(ev.Timeout)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("spec.evaluation.timeout %q is not a positive duration such as \"250ms\" or \"30s\"", ev.Timeout)
		}
		cp.Evaluation.Timeout = d
	}

	if err := checkExceptions(cp.Enforcement.Exceptions, spec.Rules); err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(spec.Rules))
	for i, r := range spec.Rules {
		// Results, fail-fast termination and `garmr test` assertions are all
		// keyed by rule id, so two rules sharing one are indistinguishable to
		// every consumer.
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true

		skippedBy, waivers := ruleExceptions(cp.Enforcement.Exceptions, r.ID)
		c := exprCompiler{builtins: e.builtins, aliases: map[string]bool{}, waivers: waivers}
		expr, err := c.expr(r.Expr, nil)
		if err != nil {
			return nil, fmt.Errorf("rule %s: expr: %w", r.ID, err)
		}
		for _, w := range c.waivers {
			if !w.attached {
				return nil, fmt.Errorf("rule %s: exception %q waives findings of a forEach with alias %q, and the rule has none", r.ID, w.name, w.as)
			}
		}
		if r.When != nil {
			guard, werr := c.expr(r.When, nil)
			if werr != nil {
				return nil, fmt.Errorf("rule %s: when: %w", r.ID, werr)
			}
			expr = whenNode{guard, expr}
		}
		msg, err := parseMessage(r.Message, c.aliases)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		details, err := parseDetails(r.Details, c.aliases)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if schema != nil {
			if err := checkRulePaths(*schema, &c, msg, details); err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		cp.Rules = append(cp.Rules, CompiledRule{
			ID:              r.ID,
			Description:     r.Description,
			Severity:        r.Severity,
			Priority:        r.Priority,
			Message:         r.Message,
			Remediation:     r.Remediation,
			Category:        r.Category,
			Tags:            r.Tags,
			DefinitionOrder: i,
			expr:            expr,
			msg:             msg,
			details:         details,
			skippedBy:       skippedBy,
			waivesElements:  len(waivers) > 0,
		})
	}
	cp.Rules = sortRules(cp.Rules, cp.Evaluation.Order)
	if schema != nil {
		if cp.inputSchema, err = inputSchemaSource(schema.schema); err != nil {
			return nil, fmt.Errorf("spec.inputSchema: %w", err)
		}
	}
	return cp, nil
}

// checkExceptions rejects exceptions that would waive more, or less, than
// they say. A policy-wide exception must narrow the inputs it applies to:
// every selector field defaults to a wildcard, so one that narrows nothing
// exempts every input and silently disables the policy. A rule-scoped
// exception must name rules that exist: a typo would waive nothing.
func checkExceptions(excs []ExceptionSpec, rules []ruleDoc) error {
	ids := make(map[string]bool, len(rules))
	for _, r := range rules {
		ids[r.ID] = true
	}
	for _, exc := range excs {
		switch {
		case exc.policyWide() && exc.Findings != nil:
			return fmt.Errorf("exception %q: findings requires rules: name the rules whose elements it waives", exc.Name)
		case exc.policyWide() && (exc.Match == nil || !exc.Match.narrows()):
			return fmt.Errorf("exception %q: match must narrow the selection (kind, apiGroup, names, namespaces, labels or annotations); an exception that matches everything disables the policy. To waive specific rules, list them in rules", exc.Name)
		}
		for _, id := range exc.Rules {
			if !ids[id] {
				return fmt.Errorf("exception %q: rule %q does not exist in this policy", exc.Name, id)
			}
		}
		if exc.Findings != nil && !identRe.MatchString(exc.Findings.As) {
			return fmt.Errorf("exception %q: findings.as must be an identifier, got %q", exc.Name, exc.Findings.As)
		}
	}
	return nil
}

// ruleExceptions returns the exceptions that skip rule id outright, and the
// element waivers its forEach nodes must attach.
func ruleExceptions(excs []ExceptionSpec, id string) (skippedBy []int, waivers []*pendingWaiver) {
	for i, exc := range excs {
		if !slices.Contains(exc.Rules, id) {
			continue
		}
		if exc.Findings == nil {
			skippedBy = append(skippedBy, i)
			continue
		}
		waivers = append(waivers, &pendingWaiver{exc: i, name: exc.Name, as: exc.Findings.As, where: exc.Findings.Where})
	}
	return skippedBy, waivers
}

// marshalSpec renders spec to JSON for decoding, leaving out inputSchema:
// a schema is a type, not data, and cannot be rendered as JSON.
func marshalSpec(spec cue.Value) ([]byte, error) {
	iter, err := spec.Fields()
	if err != nil {
		return nil, err
	}
	fields := map[string]json.RawMessage{}
	for iter.Next() {
		name := iter.Selector().Unquoted()
		if name == "inputSchema" {
			continue
		}
		b, err := iter.Value().MarshalJSON()
		if err != nil {
			return nil, err
		}
		fields[name] = b
	}
	return json.Marshal(fields)
}

// checkRulePaths checks every input path a rule reads (its expression and
// guard, message placeholders and details) against the inputSchema.
func checkRulePaths(schema schemaPathChecker, c *exprCompiler, msg msgTemplate, details []detailPath) error {
	for _, p := range c.paths {
		if err := schema.check(p); err != nil {
			return err
		}
	}
	for _, part := range msg.parts {
		if part.path == nil {
			continue
		}
		if err := checkTemplatePath(schema, c, *part.path, part.alias); err != nil {
			return fmt.Errorf("message: %w", err)
		}
	}
	for _, d := range details {
		if err := checkTemplatePath(schema, c, d.path, d.alias); err != nil {
			return fmt.Errorf("details.%s: %w", d.name, err)
		}
	}
	return nil
}

// checkTemplatePath checks a message or details path. An alias path is
// valid if it is valid for any forEach that binds the alias.
func checkTemplatePath(schema schemaPathChecker, c *exprCompiler, p fieldPath, alias bool) error {
	if !alias {
		return schema.check(recordedPath(p))
	}
	elems := c.aliasElems[p.segs[0].key]
	if len(elems) == 0 { // _index, or an alias over no input
		return nil
	}
	var first error
	for _, elem := range elems {
		segs := append(append([]pathSeg(nil), elem...), p.segs[1:]...)
		err := schema.check(recordedPath{raw: p.raw, segs: segs})
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// comparePriority orders rules with a priority before rules without, then by
// ascending priority value. 0 is a tie.
func comparePriority(a, b CompiledRule) int {
	switch {
	case a.Priority == nil && b.Priority == nil:
		return 0
	case a.Priority == nil:
		return 1
	case b.Priority == nil:
		return -1
	case *a.Priority < *b.Priority:
		return -1
	case *a.Priority > *b.Priority:
		return 1
	default:
		return 0
	}
}

// compareSeverity orders more severe rules first. 0 is a tie.
func compareSeverity(a, b CompiledRule) int {
	aw, bw := a.Severity.Weight(), b.Severity.Weight()
	switch {
	case aw > bw:
		return -1
	case aw < bw:
		return 1
	default:
		return 0
	}
}

// sortRules returns a copy of rules sorted for the given evaluation order.
// Each order is a chain of comparators with DefinitionOrder as the universal
// final tiebreak, so rules that compare equal keep their authored order.
func sortRules(rules []CompiledRule, order EvaluationOrder) []CompiledRule {
	if len(rules) == 0 {
		return rules
	}

	// Make a copy to avoid modifying the original slice order reference
	sorted := make([]CompiledRule, len(rules))
	copy(sorted, rules)

	if order == EvalOrderDefinition {
		return sorted
	}

	var chain []func(a, b CompiledRule) int
	switch order {
	case EvalOrderSeverity:
		chain = []func(a, b CompiledRule) int{compareSeverity}
	case EvalOrderPriorityThenSev:
		chain = []func(a, b CompiledRule) int{comparePriority, compareSeverity}
	default: // EvalOrderPriority and anything unrecognized
		chain = []func(a, b CompiledRule) int{comparePriority}
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		for _, cmp := range chain {
			if c := cmp(sorted[i], sorted[j]); c != 0 {
				return c < 0
			}
		}
		return sorted[i].DefinitionOrder < sorted[j].DefinitionOrder
	})

	return sorted
}
