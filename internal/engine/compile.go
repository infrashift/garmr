package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/format"
	"go.uber.org/zap"
)

// canonicalPolicyHash renders a schema-unified policy value to canonical CUE
// syntax and hashes it. Identical policy content therefore produces the same
// hash regardless of file layout, load path, or replica context — which is
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

// LoadPolicy loads and compiles a policy from CUE source. The source is
// compiled into every replica so each replica's context stays self-contained.
//
// No production path calls this — the server loads exclusively from the
// policy directory. It is kept as the engine's in-memory load API: the test
// suites across cmd/garmr, internal/server and this package build their
// fixtures with it, and it validates against the same embedded schema as the
// directory loader.
func (e *Engine) LoadPolicy(ctx context.Context, name, namespace, source string) error {
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()

	start := time.Now()

	// The reserved system namespace is used for synthetic results emitted by
	// the engine itself (e.g. no-policy-match). Reject any user policy that
	// would collide with it so that response consumers can distinguish real
	// policies from engine-generated ones by namespace alone.
	if namespace == ReservedSystemNamespace {
		e.observability().Metrics().RecordPolicyLoadError(name, namespace, "reserved_namespace")
		return fmt.Errorf("%w: namespace %q is reserved for internal use", ErrInvalidPolicy, namespace)
	}

	key := policyKey(namespace, name)

	// Two-phase: compile into every replica first, publish only if all
	// succeeded. Mutating as we go would leave a partially-loaded set on a
	// non-deterministic failure, and evaluations would then get different
	// answers depending on which replica they checked out.
	var ruleCount int
	var counts map[string]int
	err := e.set.mutateAll(func(i int, r *policyReplica) (func(), error) {
		compiled, err := e.compilePolicySource(r, name, namespace, source)
		if err != nil {
			return nil, err
		}
		compiled.LoadedAt = time.Now()

		if i == 0 {
			ruleCount = len(compiled.Rules)
			counts = namespaceCounts(r.policies, map[string]*CompiledPolicy{key: compiled})
		}

		return func() { r.policies[key] = compiled }, nil
	})
	if err != nil {
		e.observability().Metrics().RecordPolicyLoadError(name, namespace, "compilation")
		return err
	}

	e.logger.Info("policy loaded",
		zap.String("name", name),
		zap.String("namespace", namespace),
		zap.Int("rules", ruleCount),
		zap.Duration("compile_time", time.Since(start)),
	)

	e.observability().Metrics().SetPoliciesLoaded(counts)

	return nil
}

// compilePolicySource compiles and schema-validates CUE source in a replica's
// context and extracts the compiled policy.
func (e *Engine) compilePolicySource(r *policyReplica, name, namespace, source string) (*CompiledPolicy, error) {
	val := r.ctx.CompileString(source)
	if val.Err() != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, val.Err())
	}

	// Unify with schema to validate
	unified := val.Unify(r.schema.LookupPath(cue.ParsePath("#Policy")))
	if unified.Err() != nil {
		return nil, fmt.Errorf("%w: schema validation failed: %w", ErrInvalidPolicy, unified.Err())
	}

	compiled, err := e.compilePolicy(unified, name, namespace)
	if err != nil {
		return nil, fmt.Errorf("compiling policy: %w", err)
	}

	hash, err := canonicalPolicyHash(unified)
	if err != nil {
		return nil, fmt.Errorf("hashing policy: %w", err)
	}
	compiled.Hash = hash
	return compiled, nil
}

// compilePolicy extracts a CompiledPolicy from a validated CUE value.
func (e *Engine) compilePolicy(val cue.Value, name, namespace string) (*CompiledPolicy, error) {
	cp := &CompiledPolicy{
		Name:      name,
		Namespace: namespace,
		// Default evaluation config
		Evaluation: EvaluationConfig{
			Order:    EvalOrderPriority, // Default to priority-based ordering
			FailFast: false,
		},
	}

	// Extract target
	targetVal := val.LookupPath(cue.ParsePath("spec.target"))
	if targetVal.Exists() {
		target, err := e.extractTarget(targetVal)
		if err != nil {
			return nil, fmt.Errorf("extracting target: %w", err)
		}
		cp.Target = target
	}

	// Extract evaluation config (optional)
	evalVal := val.LookupPath(cue.ParsePath("spec.evaluation"))
	if evalVal.Exists() {
		evalConfig, err := e.extractEvaluationConfig(evalVal)
		if err != nil {
			return nil, fmt.Errorf("extracting evaluation config: %w", err)
		}
		cp.Evaluation = evalConfig
	}

	// Extract rules
	rulesVal := val.LookupPath(cue.ParsePath("spec.rules"))
	if rulesVal.Exists() {
		iter, err := rulesVal.List()
		if err != nil {
			return nil, fmt.Errorf("iterating rules: %w", err)
		}

		definitionOrder := 0
		for iter.Next() {
			rule, err := e.extractRule(iter.Value())
			if err != nil {
				return nil, fmt.Errorf("extracting rule: %w", err)
			}
			// Set definition order for stable sorting
			rule.DefinitionOrder = definitionOrder
			definitionOrder++
			cp.Rules = append(cp.Rules, rule)
		}
	}

	// Sort rules according to evaluation order
	cp.Rules = sortRules(cp.Rules, cp.Evaluation.Order)

	// Extract enforcement
	enfVal := val.LookupPath(cue.ParsePath("spec.enforcement"))
	if enfVal.Exists() {
		enf, err := e.extractEnforcement(enfVal)
		if err != nil {
			return nil, fmt.Errorf("extracting enforcement: %w", err)
		}
		cp.Enforcement = enf
	}

	return cp, nil
}

// extractEvaluationConfig extracts evaluation configuration from CUE value.
func (e *Engine) extractEvaluationConfig(val cue.Value) (EvaluationConfig, error) {
	config := EvaluationConfig{
		Order:    EvalOrderPriority, // Default
		FailFast: false,
	}

	if v := val.LookupPath(cue.ParsePath("order")); v.Exists() {
		orderStr, _ := v.String()
		config.Order = EvaluationOrder(orderStr)
	}

	if v := val.LookupPath(cue.ParsePath("failFast")); v.Exists() {
		config.FailFast, _ = v.Bool()
	}

	if v := val.LookupPath(cue.ParsePath("maxRules")); v.Exists() {
		mr, _ := v.Int64()
		config.MaxRules = int(mr)
	}

	if v := val.LookupPath(cue.ParsePath("timeout")); v.Exists() {
		ts, _ := v.String()
		if d, err := time.ParseDuration(ts); err == nil {
			config.Timeout = d
		}
	}

	// Extract include/exclude categories
	if v := val.LookupPath(cue.ParsePath("includeCategories")); v.Exists() {
		config.IncludeCategories = extractStringList(v)
	}
	if v := val.LookupPath(cue.ParsePath("excludeCategories")); v.Exists() {
		config.ExcludeCategories = extractStringList(v)
	}

	// Extract include/exclude tags
	if v := val.LookupPath(cue.ParsePath("includeTags")); v.Exists() {
		config.IncludeTags = extractStringList(v)
	}
	if v := val.LookupPath(cue.ParsePath("excludeTags")); v.Exists() {
		config.ExcludeTags = extractStringList(v)
	}

	return config, nil
}

// extractStringList extracts a list of strings from a CUE value.
func extractStringList(val cue.Value) []string {
	var result []string
	iter, err := val.List()
	if err != nil {
		return result
	}
	for iter.Next() {
		if s, err := iter.Value().String(); err == nil {
			result = append(result, s)
		}
	}
	return result
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

func (e *Engine) extractTarget(val cue.Value) (TargetSpec, error) {
	var target TargetSpec

	// 'conditions' was declared in the schema but never read here, so a
	// policy narrowed by conditions matched EVERYTHING. That is fail-open,
	// so reject it rather than continuing to ignore it.
	if val.LookupPath(cue.ParsePath("conditions")).Exists() {
		return target, fmt.Errorf("spec.target.conditions is not supported; scope the policy with target.resources selectors, or express the condition as a rule")
	}

	resourcesVal := val.LookupPath(cue.ParsePath("resources"))
	if resourcesVal.Exists() {
		iter, err := resourcesVal.List()
		if err != nil {
			return target, err
		}

		for iter.Next() {
			itemVal := iter.Value()

			// Check if it's a simple string (kind name) or structured selector
			if itemVal.Kind() == cue.StringKind {
				// Simple string format: "pod", "deployment", "*"
				kindStr, _ := itemVal.String()
				rs := ResourceSelector{Kind: kindStr}
				target.Resources = append(target.Resources, rs)
			} else {
				// Structured format: {kind: "pod", apiGroup: "v1", ...}
				rs, err := e.extractResourceSelector(itemVal)
				if err != nil {
					return target, err
				}
				target.Resources = append(target.Resources, rs)
			}
		}
	}

	return target, nil
}

func (e *Engine) extractResourceSelector(val cue.Value) (ResourceSelector, error) {
	var rs ResourceSelector

	if v := val.LookupPath(cue.ParsePath("apiGroup")); v.Exists() {
		s, _ := v.String()
		rs.APIGroup = s
	}

	if v := val.LookupPath(cue.ParsePath("kind")); v.Exists() {
		s, _ := v.String()
		rs.Kind = s
	}

	if v := val.LookupPath(cue.ParsePath("names")); v.Exists() {
		iter, _ := v.List()
		for iter.Next() {
			s, _ := iter.Value().String()
			rs.Names = append(rs.Names, s)
		}
	}

	if v := val.LookupPath(cue.ParsePath("namespaces")); v.Exists() {
		iter, _ := v.List()
		for iter.Next() {
			s, _ := iter.Value().String()
			rs.Namespaces = append(rs.Namespaces, s)
		}
	}

	if v := val.LookupPath(cue.ParsePath("labels")); v.Exists() {
		rs.Labels = make(map[string]string)
		iter, _ := v.Fields()
		for iter.Next() {
			s, _ := iter.Value().String()
			rs.Labels[iter.Selector().String()] = s
		}
	}

	if v := val.LookupPath(cue.ParsePath("annotations")); v.Exists() {
		rs.Annotations = make(map[string]string)
		iter, _ := v.Fields()
		for iter.Next() {
			s, _ := iter.Value().String()
			rs.Annotations[iter.Selector().String()] = s
		}
	}

	return rs, nil
}

func (e *Engine) extractRule(val cue.Value) (CompiledRule, error) {
	var rule CompiledRule

	if v := val.LookupPath(cue.ParsePath("id")); v.Exists() {
		rule.ID, _ = v.String()
	}

	if v := val.LookupPath(cue.ParsePath("description")); v.Exists() {
		rule.Description, _ = v.String()
	}

	if v := val.LookupPath(cue.ParsePath("severity")); v.Exists() {
		s, _ := v.String()
		rule.Severity = Severity(s)
	}

	if v := val.LookupPath(cue.ParsePath("message")); v.Exists() {
		rule.Message, _ = v.String()
	}

	// Extract priority (optional)
	if v := val.LookupPath(cue.ParsePath("priority")); v.Exists() {
		p, err := v.Int64()
		if err == nil {
			pi := int(p)
			rule.Priority = &pi
		}
	}

	// Extract remediation (optional)
	if v := val.LookupPath(cue.ParsePath("remediation")); v.Exists() {
		rule.Remediation, _ = v.String()
	}

	// Extract category (optional)
	if v := val.LookupPath(cue.ParsePath("category")); v.Exists() {
		rule.Category, _ = v.String()
	}

	// Extract tags (optional)
	if v := val.LookupPath(cue.ParsePath("tags")); v.Exists() {
		iter, err := v.List()
		if err == nil {
			for iter.Next() {
				if tag, err := iter.Value().String(); err == nil {
					rule.Tags = append(rule.Tags, tag)
				}
			}
		}
	}

	// 'continueOnFail' was extracted but never consulted during evaluation,
	// so `continueOnFail: false` silently did nothing. Reject it and point
	// authors at the mechanism that does work.
	if val.LookupPath(cue.ParsePath("continueOnFail")).Exists() {
		return rule, fmt.Errorf("rule %s: 'continueOnFail' is not supported; use spec.evaluation.failFast to stop on the first failure", rule.ID)
	}

	rule.Expression = val.LookupPath(cue.ParsePath("expr"))

	// 'ref' was removed from the policy schema without ever being
	// implemented. Reject it at compile time so authors find out
	// immediately instead of via an always-failing rule.
	if rule.Expression.Exists() && rule.Expression.LookupPath(cue.ParsePath("ref")).Exists() {
		return rule, fmt.Errorf("rule %s: expr 'ref' is not supported", rule.ID)
	}

	return rule, nil
}

func (e *Engine) extractEnforcement(val cue.Value) (EnforcementSpec, error) {
	var enf EnforcementSpec

	// 'webhook' was declared in the schema and never read, so it implied a
	// callout on violation that never happened.
	if val.LookupPath(cue.ParsePath("webhook")).Exists() {
		return enf, fmt.Errorf("spec.enforcement.webhook is not supported; Garmr does not call out on a violation. Consume the evaluation response instead")
	}

	if v := val.LookupPath(cue.ParsePath("action")); v.Exists() {
		enf.Action, _ = v.String()
	}

	if v := val.LookupPath(cue.ParsePath("dryRun")); v.Exists() {
		enf.DryRun, _ = v.Bool()
	}

	// Extract exceptions
	if exceptionsVal := val.LookupPath(cue.ParsePath("exceptions")); exceptionsVal.Exists() {
		iter, _ := exceptionsVal.List()
		for iter.Next() {
			excVal := iter.Value()
			var exc ExceptionSpec
			// extract name, reason, match fields, expiry
			if v := excVal.LookupPath(cue.ParsePath("name")); v.Exists() {
				exc.Name, _ = v.String()
			}
			if v := excVal.LookupPath(cue.ParsePath("reason")); v.Exists() {
				exc.Reason, _ = v.String()
			}
			// extract match (ResourceSelector)
			if matchVal := excVal.LookupPath(cue.ParsePath("match")); matchVal.Exists() {
				rs, err := e.extractResourceSelector(matchVal)
				if err == nil {
					exc.Match = rs
				}
			}
			// extract expiry
			if v := excVal.LookupPath(cue.ParsePath("expiry")); v.Exists() {
				if expiryStr, err := v.String(); err == nil {
					if t, err := time.Parse(time.RFC3339, expiryStr); err == nil {
						exc.Expiry = &t
					}
				}
			}
			enf.Exceptions = append(enf.Exceptions, exc)
		}
	}

	return enf, nil
}
