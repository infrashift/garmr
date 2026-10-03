package engine

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Evaluate evaluates input against loaded policies.
func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	// A caller whose deadline has already passed (or whose client hung up)
	// gets no work done on its behalf. Callers surface this as
	// backpressure — 503, not a decision.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvaluationUnavailable, err)
	}

	set := e.set.Load()
	requireMatch := e.requireMatch.Load()

	e.observability().Metrics().IncActiveEvaluations()
	defer e.observability().Metrics().DecActiveEvaluations()

	input, err := normalizeInput(req.Input)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp := &EvaluateResponse{
		Decision: DecisionAllow,
		Metrics:  &Metrics{},
	}

	// Find applicable policies
	res := resourceOf(input)
	policies := e.findApplicablePolicies(set, req, res)
	resp.Metrics.PoliciesEvaluated = len(policies)

	// Fail-closed on no match. Returning DecisionAllow with zero rules
	// evaluated is a silent pass — a typo in --namespace or a missing
	// policy looks identical to a clean bill of health. When requireMatch
	// is set we emit DecisionDeny with a synthetic RuleResult explaining
	// which of the four failure modes (no policies loaded, named policy
	// missing, empty namespace, or no target match) applied.
	if len(policies) == 0 && requireMatch {
		resp.Decision = DecisionDeny
		resp.Results = append(resp.Results, e.buildNoMatchResult(set, req))
		resp.Metrics.EvaluationTimeNs = time.Since(start).Nanoseconds()
		e.observability().Metrics().RecordEvaluation(
			"",
			req.Namespace,
			string(resp.Decision),
			"",
			time.Since(start),
		)
		return resp, nil
	}

	// Timeout enforcement: the minimum timeout across all policies bounds
	// the whole evaluation.
	if minTimeout := minPolicyTimeout(policies); minTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, minTimeout)
		defer cancel()
	}

	// Count rules actually in scope (after category/tag filters, exceptions,
	// and maxRules caps) so fail-fast skip counts and the summary are accurate.
	totalRulesInScope := 0
	for _, p := range policies {
		totalRulesInScope += e.countRulesInScope(p, res)
	}
	acc := newEvalAccumulator(resp, totalRulesInScope)

	// Evaluate each policy, folding every outcome into the response. Each
	// fold reports whether the evaluation must stop (engine failure,
	// timeout, or fail-fast).
	for _, policy := range policies {
		outcome := e.evaluatePolicy(ctx, policy, input, res)
		if stop := acc.fold(e, policy, outcome, req, ctx.Err()); stop {
			break
		}
	}

	acc.finish()

	resp.Metrics.EvaluationTimeNs = time.Since(start).Nanoseconds()

	// Record evaluation metric
	e.observability().Metrics().RecordEvaluation(
		"",                    // policy name (we evaluate multiple)
		req.Namespace,         // namespace
		string(resp.Decision), // decision
		"",                    // environment
		time.Since(start),     // duration
	)

	return resp, nil
}

// minPolicyTimeout returns the smallest configured per-policy timeout, or 0
// when no policy sets one.
func minPolicyTimeout(policies []*CompiledPolicy) time.Duration {
	min := time.Duration(0)
	for _, p := range policies {
		if p.Evaluation.Timeout > 0 && (min == 0 || p.Evaluation.Timeout < min) {
			min = p.Evaluation.Timeout
		}
	}
	return min
}

// evalAccumulator folds per-policy outcomes into an EvaluateResponse,
// tracking the scope counters that make partial evaluations visible.
type evalAccumulator struct {
	resp              *EvaluateResponse
	totalRulesInScope int
	rulesEvaluated    int
}

func newEvalAccumulator(resp *EvaluateResponse, totalRulesInScope int) *evalAccumulator {
	resp.Summary.TotalRules = totalRulesInScope
	return &evalAccumulator{resp: resp, totalRulesInScope: totalRulesInScope}
}

// fold merges one policy's outcome and reports whether evaluation must stop.
func (a *evalAccumulator) fold(e *Engine, policy *CompiledPolicy, outcome policyOutcome, req *EvaluateRequest, ctxErr error) (stop bool) {
	// A deadline that expires partway through a policy means some rules
	// never ran. Deny unconditionally: unlike a rule violation this is an
	// engine failure, so `enforcement.action: "warn"` and dry-run must not
	// be able to downgrade it.
	if outcome.timedOut {
		a.resp.Decision = DecisionDeny
		a.resp.Results = append(a.resp.Results, buildTimeoutResult(policy, ctxErr))
		a.setScopeCounts()
		return true
	}

	results := outcome.results
	a.rulesEvaluated += len(results)
	a.resp.Metrics.RulesEvaluated += len(results)

	isDryRun := policy.Enforcement.DryRun

	// Compute this policy's effective decision in isolation, then merge.
	// A dry-run policy is capped at Warn but must never lower a Deny
	// that another (enforcing) policy has already produced.
	policyDecision := DecisionAllow

	for _, result := range results {
		if result.Passed {
			a.resp.Summary.Passed++
		} else {
			a.resp.Summary.Failed++
			e.observability().Metrics().RecordViolation(policy.Name, policy.Namespace, result.RuleID, string(result.Severity))

			switch policy.Enforcement.Action {
			case "deny":
				policyDecision = maxDecision(policyDecision, DecisionDeny)
			case "warn":
				policyDecision = maxDecision(policyDecision, DecisionWarn)
			}

			if isDryRun {
				result.Message = "[DRY RUN] " + result.Message
			}
		}

		if !result.Passed || req.Options.IncludePassed {
			a.resp.Results = append(a.resp.Results, result)
		}
	}

	// Dry run: this policy's deny becomes a warn
	if isDryRun && policyDecision == DecisionDeny {
		policyDecision = DecisionWarn
	}
	a.resp.Decision = maxDecision(a.resp.Decision, policyDecision)
	if isDryRun {
		a.resp.EvaluationMode.DryRun = true
	}

	if outcome.failFast {
		a.noteFailFast(results)
		return true
	}
	return false
}

// noteFailFast marks the response as short-circuited by the last failing
// result of the terminating policy.
func (a *evalAccumulator) noteFailFast(results []RuleResult) {
	var lastFailed *RuleResult
	for i := len(results) - 1; i >= 0; i-- {
		if !results[i].Passed {
			r := results[i]
			r.CausedTermination = true
			lastFailed = &r
			break
		}
	}

	a.resp.TerminatedEarly = true
	a.resp.TerminationRule = lastFailed
	a.resp.EvaluationMode.FailFast = true
	a.resp.EvaluationMode.ShortCircuited = true
	a.setScopeCounts()
}

// setScopeCounts publishes the in-scope/evaluated/skipped counters.
func (a *evalAccumulator) setScopeCounts() {
	a.resp.EvaluationMode.TotalRulesInScope = a.totalRulesInScope
	a.resp.EvaluationMode.RulesEvaluated = a.rulesEvaluated
	a.resp.EvaluationMode.RulesSkipped = a.totalRulesInScope - a.rulesEvaluated
}

// finish fills the summary skip count and, when nothing terminated early,
// the scope counters. Always reporting them is the point of evaluation_mode:
// a caller cannot tell a full evaluation from a partial one otherwise.
func (a *evalAccumulator) finish() {
	a.resp.Summary.Skipped = a.totalRulesInScope - a.rulesEvaluated
	if a.resp.EvaluationMode.TotalRulesInScope == 0 {
		a.setScopeCounts()
	}
}

// findApplicablePolicies returns the policies that apply to the request.
func (e *Engine) findApplicablePolicies(set *policySet, req *EvaluateRequest, res resource) []*CompiledPolicy {
	var result []*CompiledPolicy

	// If specific policies requested, return only those, in request order.
	if len(req.Policies) > 0 {
		seen := make(map[string]bool, len(req.Policies))
		for _, name := range req.Policies {
			key := policyKey(req.Namespace, name)
			if seen[key] {
				continue // naming a policy twice must not evaluate it twice
			}
			seen[key] = true
			if p, ok := set.policies[key]; ok && e.policyMatchesInput(p, res) {
				result = append(result, p)
			}
		}
		return result
	}

	// Otherwise every policy in the namespace whose target matches. The kind
	// index narrows the candidates; they come back sorted, so results
	// ordering, fail-fast winners and timeout tie-breaks are reproducible.
	for _, p := range set.candidates(res.kind) {
		if (req.Namespace == "" || p.Namespace == req.Namespace) && e.policyMatchesInput(p, res) {
			result = append(result, p)
		}
	}
	return result
}

// countRulesInScope returns the number of rules of a policy that would be
// evaluated for this request: rules surviving category/tag filters, zero when
// an exception matches, capped by the policy's maxRules setting.
func (e *Engine) countRulesInScope(policy *CompiledPolicy, res resource) int {
	if len(policy.Enforcement.Exceptions) > 0 && e.matchesException(policy.Enforcement.Exceptions, res) {
		return 0
	}
	n := 0
	for _, rule := range policy.Rules {
		if shouldEvaluateRule(rule, policy.Evaluation) {
			n++
		}
	}
	if policy.Evaluation.MaxRules > 0 && n > policy.Evaluation.MaxRules {
		n = policy.Evaluation.MaxRules
	}
	return n
}

// resource identifies an input for target and exception matching. It is
// computed once per evaluation; labels and annotations are read in place.
type resource struct {
	kind, group, name, namespace string
	labels, annotations          map[string]any
}

func resourceOf(input map[string]any) resource {
	md, _ := input["metadata"].(map[string]any)
	r := resource{
		kind:      NestedString(input, "kind"),
		group:     apiGroupOf(NestedString(input, "apiVersion")),
		name:      NestedString(md, "name"),
		namespace: NestedString(md, "namespace"),
	}
	r.labels, _ = md["labels"].(map[string]any)
	r.annotations, _ = md["annotations"].(map[string]any)
	return r
}

// policyMatchesInput checks if a policy's target matches the input resource.
func (e *Engine) policyMatchesInput(policy *CompiledPolicy, res resource) bool {
	// If no target resources defined, policy applies to everything
	if len(policy.Target.Resources) == 0 {
		return true
	}
	for _, selector := range policy.Target.Resources {
		if e.selectorMatchesInput(selector, res) {
			return true
		}
	}
	return false
}

// apiGroupOf returns the API group of a Kubernetes-style apiVersion:
// "apps/v1" -> "apps", and "v1" (no slash) -> "" (the core group).
func apiGroupOf(apiVersion string) string {
	if i := strings.LastIndex(apiVersion, "/"); i >= 0 {
		return apiVersion[:i]
	}
	return ""
}

// selectorMatchesInput checks if a resource selector matches the input.
func (e *Engine) selectorMatchesInput(selector ResourceSelector, res resource) bool {
	if selector.Kind != "" && selector.Kind != "*" && !e.matchesPatternCached(selector.Kind, res.kind) {
		return false
	}
	// "" is the core group, so only "*" is a wildcard.
	if selector.APIGroup != "*" && !e.matchesPatternCached(selector.APIGroup, res.group) {
		return false
	}
	if len(selector.Names) > 0 && !e.anyPatternMatches(selector.Names, res.name) {
		return false
	}
	if len(selector.Namespaces) > 0 && !e.anyPatternMatches(selector.Namespaces, res.namespace) {
		return false
	}
	// Every specified label and annotation must match.
	for k, v := range selector.Labels {
		if got, ok := res.labels[k].(string); !ok || !e.matchesPatternCached(v, got) {
			return false
		}
	}
	for k, v := range selector.Annotations {
		if got, ok := res.annotations[k].(string); !ok || !e.matchesPatternCached(v, got) {
			return false
		}
	}
	return true
}

func (e *Engine) anyPatternMatches(patterns []string, value string) bool {
	for _, p := range patterns {
		if e.matchesPatternCached(p, value) {
			return true
		}
	}
	return false
}

// policyOutcome is the result of evaluating one policy: the per-rule results,
// whether fail-fast stopped the policy, and whether the evaluation deadline
// expired partway through. timedOut is reported rather than folded into
// results because a deadline is an engine failure, not a policy verdict — see
// Evaluate, which turns it into an unconditional deny.
type policyOutcome struct {
	results  []RuleResult
	failFast bool
	timedOut bool
}

// evaluatePolicy evaluates a single policy against input.
func (e *Engine) evaluatePolicy(ctx context.Context, policy *CompiledPolicy, input map[string]any, res resource) policyOutcome {
	var out policyOutcome

	// Check if any exception matches the input, skip evaluation if so
	if len(policy.Enforcement.Exceptions) > 0 && e.matchesException(policy.Enforcement.Exceptions, res) {
		return out
	}
	out.results = make([]RuleResult, 0, len(policy.Rules))

	ec := &evalCtx{ctx: ctx, done: ctx.Done(), root: input}
	for _, rule := range policy.Rules {
		if !shouldEvaluateRule(rule, policy.Evaluation) {
			continue
		}

		// Timeout check: if the context has been cancelled/timed out, stop
		// evaluating and report it. Emitting a passing synthetic result here
		// would fail open — a policy whose rules never ran would return
		// ALLOW, which is exactly the silent pass the no-match handling
		// exists to prevent.
		if ctx.Err() != nil {
			out.timedOut = true
			return out
		}

		result := e.evaluateRule(ec, policy, rule)
		// A deadline that expired during the rule (inside a forEach) means
		// the rule did not finish: that is a timeout, not a verdict.
		if ctx.Err() != nil {
			out.timedOut = true
			return out
		}
		out.results = append(out.results, result)

		if policy.Evaluation.FailFast && !result.Passed {
			out.failFast = true
			return out
		}

		if policy.Evaluation.MaxRules > 0 && len(out.results) >= policy.Evaluation.MaxRules {
			break
		}
	}

	return out
}

// buildTimeoutResult returns the synthetic failing result emitted when a
// policy's evaluation deadline expires. It mirrors buildNoMatchResult: both
// are engine-level failures surfaced in the reserved system namespace so they
// cannot be confused with a policy's own verdict.
func buildTimeoutResult(policy *CompiledPolicy, cause error) RuleResult {
	timeout := policy.Evaluation.Timeout
	message := fmt.Sprintf("Evaluation of policy %s/%s exceeded its deadline (%s) and was denied.",
		policy.Namespace, policy.Name, timeout)
	if timeout <= 0 {
		message = fmt.Sprintf("Evaluation of policy %s/%s was cancelled before completing (%v) and was denied.",
			policy.Namespace, policy.Name, cause)
	}

	return RuleResult{
		PolicyNamespace: ReservedSystemNamespace,
		PolicyName:      SystemPolicyNameTimeout,
		RuleID:          RuleIDTimeout,
		RuleDescription: "Policy evaluation did not complete",
		Severity:        SeverityCritical,
		Passed:          false,
		Message:         message,
		Remediation:     "Raise `spec.evaluation.timeout` for this policy or simplify its rules. Rules that did not run are not evidence of compliance, so the evaluation fails closed.",
		Bindings:        map[string]any{},
	}
}

// evaluateRule evaluates a single rule against input.
func (e *Engine) evaluateRule(ec *evalCtx, policy *CompiledPolicy, rule CompiledRule) RuleResult {
	result := RuleResult{
		PolicyName:      policy.Name,
		PolicyNamespace: policy.Namespace,
		RuleID:          rule.ID,
		RuleDescription: rule.Description,
		Severity:        rule.Severity,
		Remediation:     rule.Remediation,
		Priority:        rule.Priority,
		Category:        rule.Category,
		Tags:            rule.Tags,
	}

	ec.wantBinds, ec.wantFrames = rule.msg.hasBinds, rule.msg.hasFrames
	ec.binds, ec.failures = ec.binds[:0], ec.failures[:0]
	r := rule.expr.eval(ec)

	// Anything but a pass fails the rule. An error is reported, never
	// inverted or skipped.
	result.Passed = r.out == pass
	if len(ec.binds) > 0 {
		result.Bindings = make(map[string]any, len(ec.binds))
		for _, b := range ec.binds {
			result.Bindings[b.name] = b.value
		}
	}

	if !result.Passed {
		switch {
		case r.out == errored:
			// The rule could not be evaluated as written; the author's
			// message would misdescribe that, so say what went wrong.
			result.Message = fmt.Sprintf("Rule %s could not be evaluated: %s", rule.ID, r.msg)
		case rule.Message != "":
			result.Message = rule.msg.message(ec.root, result.Bindings, ec.failures)
		case r.msg != "":
			result.Message = r.msg
		default:
			result.Message = fmt.Sprintf("Rule %s failed: %s", rule.ID, rule.Description)
		}
	}

	return result
}

// shouldEvaluateRule returns false if the policy's category/tag filters
// exclude the rule.
func shouldEvaluateRule(rule CompiledRule, cfg EvaluationConfig) bool {
	if len(cfg.IncludeCategories) > 0 && !stringInSlice(rule.Category, cfg.IncludeCategories) {
		return false
	}
	if len(cfg.ExcludeCategories) > 0 && stringInSlice(rule.Category, cfg.ExcludeCategories) {
		return false
	}
	if len(cfg.IncludeTags) > 0 && !anyTagMatches(rule.Tags, cfg.IncludeTags) {
		return false
	}
	if len(cfg.ExcludeTags) > 0 && anyTagMatches(rule.Tags, cfg.ExcludeTags) {
		return false
	}
	return true
}

// matchesException checks if any non-expired exception matches the input.
func (e *Engine) matchesException(exceptions []ExceptionSpec, res resource) bool {
	now := time.Now()
	for _, exc := range exceptions {
		if exc.Expiry != nil && now.After(*exc.Expiry) {
			continue
		}
		if e.selectorMatchesInput(exc.Match, res) {
			return true
		}
	}
	return false
}

// buildNoMatchResult produces the synthetic RuleResult that accompanies a
// fail-closed DecisionDeny when zero policies matched. The message is
// tailored to the most specific cause the engine can identify from the
// request and the current policy set, so users get actionable remediation
// (typo'd namespace, missing policy name, or target-selector mismatch)
// instead of a generic deny.
func (e *Engine) buildNoMatchResult(set *policySet, req *EvaluateRequest) RuleResult {
	const remediation = "Verify the namespace and policy names in your request, and run `garmr policy list` to inspect loaded policies."

	var message string
	switch {
	case len(set.policies) == 0:
		message = "No policies are loaded on the server. Check the server's policy directory and ensure policies compiled successfully."
	case len(req.Policies) > 0:
		ns := req.Namespace
		if ns == "" {
			ns = "default"
		}
		var missing []string
		for _, name := range req.Policies {
			if _, ok := set.policies[policyKey(ns, name)]; !ok {
				missing = append(missing, fmt.Sprintf("%s/%s", ns, name))
			}
		}
		if len(missing) > 0 {
			message = fmt.Sprintf("Policy %s not found. Run `garmr policy list` to see available policies.", strings.Join(missing, ", "))
		} else {
			message = fmt.Sprintf("Requested policies exist but none target this input (kind=%q apiVersion=%q). Check the target selectors on %s.",
				NestedString(req.Input, "kind"),
				NestedString(req.Input, "apiVersion"),
				strings.Join(req.Policies, ", "),
			)
		}
	case req.Namespace != "" && !namespaceHasPolicies(set, req.Namespace):
		message = fmt.Sprintf("No policies found in namespace %q. Run `garmr policy list` to see available namespaces.", req.Namespace)
	default:
		message = fmt.Sprintf("No policy targets this input (kind=%q apiVersion=%q). Check resource selectors on your policies or the `kind` field of your input.",
			NestedString(req.Input, "kind"),
			NestedString(req.Input, "apiVersion"),
		)
	}

	return RuleResult{
		PolicyNamespace: ReservedSystemNamespace,
		PolicyName:      SystemPolicyNameMatch,
		RuleID:          RuleIDNoMatch,
		RuleDescription: "No policy matched the evaluation request",
		Severity:        SeverityHigh,
		Passed:          false,
		Message:         message,
		Remediation:     remediation,
		Bindings:        map[string]any{},
	}
}

// namespaceHasPolicies reports whether any policy in the set belongs to ns.
func namespaceHasPolicies(set *policySet, ns string) bool {
	for _, p := range set.all {
		if p.Namespace == ns {
			return true
		}
	}
	return false
}
