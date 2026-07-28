package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"go.uber.org/zap"
)

// Evaluate evaluates input against loaded policies.
func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	e.mu.RLock()
	set := e.set
	requireMatch := e.requireMatch
	e.mu.RUnlock()

	// Track active evaluations for metrics
	e.observability().Metrics().IncActiveEvaluations()
	defer e.observability().Metrics().DecActiveEvaluations()

	// Check out a policy replica for the duration of this evaluation. The
	// replica's CUE context and every compiled policy value in it form a
	// single unit, so the input and the policy expressions it unifies with
	// always share one context, and no two goroutines ever share one.
	rep := set.get()
	defer set.put(rep)

	// Store the replica's CUE context in the Go context so all downstream
	// evaluation methods can access it without signature changes.
	ctx = withCueContext(ctx, rep.ctx)

	start := time.Now()
	resp := &EvaluateResponse{
		Decision: DecisionAllow,
		Metrics:  &Metrics{},
	}

	// Convert input to CUE value using the replica's context
	inputVal := rep.ctx.Encode(req.Input)
	if inputVal.Err() != nil {
		return nil, fmt.Errorf("%w: encoding input: %v", ErrInvalidInput, inputVal.Err())
	}

	// Find applicable policies
	policies := e.findApplicablePolicies(rep, req)
	resp.Metrics.PoliciesEvaluated = len(policies)

	// Fail-closed on no match. Returning DecisionAllow with zero rules
	// evaluated is a silent pass — a typo in --namespace or a missing
	// policy looks identical to a clean bill of health. When requireMatch
	// is set we emit DecisionDeny with a synthetic RuleResult explaining
	// which of the four failure modes (no policies loaded, named policy
	// missing, empty namespace, or no target match) applied.
	if len(policies) == 0 && requireMatch {
		resp.Decision = DecisionDeny
		resp.Results = append(resp.Results, e.buildNoMatchResult(rep, req))
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

	// Timeout enforcement: find the minimum timeout across all policies
	minTimeout := time.Duration(0)
	for _, p := range policies {
		if p.Evaluation.Timeout > 0 {
			if minTimeout == 0 || p.Evaluation.Timeout < minTimeout {
				minTimeout = p.Evaluation.Timeout
			}
		}
	}
	if minTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, minTimeout)
		defer cancel()
	}

	// Count rules actually in scope (after category/tag filters, exceptions,
	// and maxRules caps) so fail-fast skip counts and the summary are accurate.
	totalRulesInScope := 0
	for _, p := range policies {
		totalRulesInScope += e.countRulesInScope(p, req)
	}
	rulesEvaluated := 0
	resp.Summary.TotalRules = totalRulesInScope
	// Initialise eagerly so a response with zero results still serialises
	// empty maps rather than null.
	resp.Summary.BySeverity = make(map[Severity]SeverityCounts)
	resp.Summary.ByCategory = make(map[string]CategoryCounts)
	resp.Summary.ByNamespace = make(map[string]NamespaceCounts)

	// Evaluate each policy
	for _, policy := range policies {
		outcome, err := e.evaluatePolicy(ctx, policy, inputVal, req)
		if err != nil {
			// Fail closed: a policy that could not be evaluated is not
			// evidence of compliance. Continuing here would let the overall
			// decision stay Allow while a rule silently never ran.
			e.logger.Error("policy evaluation failed",
				zap.String("policy", policy.Name),
				zap.String("namespace", policy.Namespace),
				zap.Error(err),
			)
			resp.Decision = DecisionDeny
			resp.Results = append(resp.Results, buildEvaluationErrorResult(policy, err))
			break
		}

		// A deadline that expires partway through a policy means some rules
		// never ran. Deny unconditionally: unlike a rule violation this is an
		// engine failure, so `enforcement.action: "warn"` and dry-run must not
		// be able to downgrade it.
		if outcome.timedOut {
			resp.Decision = DecisionDeny
			resp.Results = append(resp.Results, buildTimeoutResult(policy, ctx.Err()))
			resp.EvaluationMode.TotalRulesInScope = totalRulesInScope
			resp.EvaluationMode.RulesEvaluated = rulesEvaluated
			resp.EvaluationMode.RulesSkipped = totalRulesInScope - rulesEvaluated
			break
		}

		results := outcome.results
		failFastTriggered := outcome.failFast

		rulesEvaluated += len(results)
		resp.Metrics.RulesEvaluated += len(results)

		// Determine dry run mode
		isDryRun := false
		if req.Options.DryRunOverride != nil {
			isDryRun = *req.Options.DryRunOverride
		} else {
			isDryRun = policy.Enforcement.DryRun
		}

		// Compute this policy's effective decision in isolation, then merge.
		// A dry-run policy is capped at Warn but must never lower a Deny
		// that another (enforcing) policy has already produced.
		policyDecision := DecisionAllow

		for _, result := range results {
			e.recordSummary(&resp.Summary, policy, result)

			if !result.Passed {
				// Record violation metric
				e.observability().Metrics().RecordViolation(policy.Name, policy.Namespace, result.RuleID, string(result.Severity))

				// Update decision based on enforcement action
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

			// Include result based on options
			if !result.Passed || req.Options.IncludePassed {
				resp.Results = append(resp.Results, result)
			}
		}

		// Dry run: this policy's deny becomes a warn
		if isDryRun && policyDecision == DecisionDeny {
			policyDecision = DecisionWarn
		}
		resp.Decision = maxDecision(resp.Decision, policyDecision)

		// Set dry run mode info
		if isDryRun {
			resp.EvaluationMode.DryRun = true
		}

		// Handle fail-fast termination
		if failFastTriggered {
			// Find the last failed result
			var lastFailed *RuleResult
			for i := len(results) - 1; i >= 0; i-- {
				if !results[i].Passed {
					r := results[i]
					r.CausedTermination = true
					lastFailed = &r
					break
				}
			}

			resp.TerminatedEarly = true
			resp.TerminationRule = lastFailed
			resp.EvaluationMode.FailFast = true
			resp.EvaluationMode.ShortCircuited = true
			resp.EvaluationMode.TotalRulesInScope = totalRulesInScope
			resp.EvaluationMode.RulesEvaluated = rulesEvaluated
			resp.EvaluationMode.RulesSkipped = totalRulesInScope - rulesEvaluated
			break
		}
	}

	resp.Summary.Skipped = totalRulesInScope - rulesEvaluated

	// Always report the scope counts, not only when something terminated
	// early. A caller cannot tell a full evaluation from a partial one
	// otherwise, which is the whole point of exposing evaluation_mode.
	if resp.EvaluationMode.TotalRulesInScope == 0 {
		resp.EvaluationMode.TotalRulesInScope = totalRulesInScope
		resp.EvaluationMode.RulesEvaluated = rulesEvaluated
		resp.EvaluationMode.RulesSkipped = totalRulesInScope - rulesEvaluated
	}

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

// findApplicablePolicies returns policies from the replica that match the request.
func (e *Engine) findApplicablePolicies(rep *policyReplica, req *EvaluateRequest) []*CompiledPolicy {
	var result []*CompiledPolicy

	// If specific policies requested, return only those
	if len(req.Policies) > 0 {
		for _, name := range req.Policies {
			ns := req.Namespace
			if ns == "" {
				ns = "default"
			}
			key := policyKey(ns, name)
			if p, ok := rep.policies[key]; ok {
				if e.policyMatchesInput(p, req.Input) {
					result = append(result, p)
				}
			}
		}
		return result
	}

	// Otherwise, return all policies in namespace that match the input
	for _, p := range rep.policies {
		if req.Namespace == "" || p.Namespace == req.Namespace {
			if e.policyMatchesInput(p, req.Input) {
				result = append(result, p)
			}
		}
	}

	// Map iteration order is random; sort so results ordering, fail-fast
	// winners, and timeout tie-breaks are reproducible across runs.
	sort.Slice(result, func(i, j int) bool {
		return policyKey(result[i].Namespace, result[i].Name) < policyKey(result[j].Namespace, result[j].Name)
	})

	return result
}

// countRulesInScope returns the number of rules of a policy that would be
// evaluated for this request: rules surviving category/tag filters, zero when
// an exception matches, capped by the policy's maxRules setting.
func (e *Engine) countRulesInScope(policy *CompiledPolicy, req *EvaluateRequest) int {
	if len(policy.Enforcement.Exceptions) > 0 && e.matchesException(policy.Enforcement.Exceptions, req.Input) {
		return 0
	}
	n := 0
	for _, rule := range policy.Rules {
		if e.shouldEvaluateRule(rule, policy.Evaluation, req.Options) {
			n++
		}
	}
	if policy.Evaluation.MaxRules > 0 && n > policy.Evaluation.MaxRules {
		n = policy.Evaluation.MaxRules
	}
	return n
}

// recordSummary updates the response summary counts for a single rule result.
func (e *Engine) recordSummary(s *ResultSummary, policy *CompiledPolicy, result RuleResult) {
	if s.BySeverity == nil {
		s.BySeverity = make(map[Severity]SeverityCounts)
		s.ByCategory = make(map[string]CategoryCounts)
		s.ByNamespace = make(map[string]NamespaceCounts)
	}

	sev := s.BySeverity[result.Severity]
	cat := s.ByCategory[result.Category]
	ns := s.ByNamespace[policy.Namespace]
	if result.Passed {
		s.Passed++
		sev.Passed++
		cat.Passed++
		ns.Passed++
	} else {
		s.Failed++
		sev.Failed++
		cat.Failed++
		ns.Failed++
	}
	s.BySeverity[result.Severity] = sev
	s.ByCategory[result.Category] = cat
	s.ByNamespace[policy.Namespace] = ns
}

// policyMatchesInput checks if a policy's target matches the input resource.
func (e *Engine) policyMatchesInput(policy *CompiledPolicy, input map[string]any) bool {
	// If no target resources defined, policy applies to everything
	if len(policy.Target.Resources) == 0 {
		return true
	}

	// Extract resource identifiers from input
	inputKind := getStringField(input, "kind")
	inputAPIGroup := getStringField(input, "apiVersion")
	inputName := getStringField(input, "metadata", "name")
	inputNamespace := getStringField(input, "metadata", "namespace")
	inputLabels := getMapField(input, "metadata", "labels")
	inputAnnotations := getMapField(input, "metadata", "annotations")

	// Check if any target selector matches
	for _, selector := range policy.Target.Resources {
		if e.selectorMatchesInput(selector, inputKind, inputAPIGroup, inputName, inputNamespace, inputLabels, inputAnnotations) {
			return true
		}
	}

	return false
}

// selectorMatchesInput checks if a resource selector matches the input.
func (e *Engine) selectorMatchesInput(selector ResourceSelector, kind, apiGroup, name, namespace string, labels, annotations map[string]string) bool {
	// Check Kind (supports wildcards)
	if selector.Kind != "" && selector.Kind != "*" {
		if !e.matchesPatternCached(selector.Kind, kind) {
			return false
		}
	}

	// Check APIGroup
	if selector.APIGroup != "" && selector.APIGroup != "*" {
		if !e.matchesPatternCached(selector.APIGroup, apiGroup) {
			return false
		}
	}

	// Check Names (if specified, name must be in the list)
	if len(selector.Names) > 0 {
		found := false
		for _, n := range selector.Names {
			if e.matchesPatternCached(n, name) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check Namespaces (if specified, namespace must be in the list)
	if len(selector.Namespaces) > 0 {
		found := false
		for _, ns := range selector.Namespaces {
			if e.matchesPatternCached(ns, namespace) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check Labels (all specified labels must match)
	if len(selector.Labels) > 0 {
		for k, v := range selector.Labels {
			if labelVal, ok := labels[k]; !ok || !e.matchesPatternCached(v, labelVal) {
				return false
			}
		}
	}

	// Check Annotations (all specified annotations must match)
	if len(selector.Annotations) > 0 {
		for k, v := range selector.Annotations {
			if annVal, ok := annotations[k]; !ok || !e.matchesPatternCached(v, annVal) {
				return false
			}
		}
	}

	return true
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
func (e *Engine) evaluatePolicy(ctx context.Context, policy *CompiledPolicy, input cue.Value, req *EvaluateRequest) (policyOutcome, error) {
	var out policyOutcome
	opts := req.Options

	// Check if any exception matches the input, skip evaluation if so
	if len(policy.Enforcement.Exceptions) > 0 {
		if e.matchesException(policy.Enforcement.Exceptions, req.Input) {
			return out, nil
		}
	}

	for _, rule := range policy.Rules {
		// Category/tag filtering: skip rules that don't match filters
		if !e.shouldEvaluateRule(rule, policy.Evaluation, opts) {
			continue
		}

		// Timeout check: if the context has been cancelled/timed out, stop
		// evaluating and report it. Emitting a passing synthetic result here
		// would fail open — a policy whose rules never ran would return
		// ALLOW, which is exactly the silent pass the no-match handling
		// exists to prevent.
		if ctx.Err() != nil {
			out.timedOut = true
			return out, nil
		}

		result := e.evaluateRule(ctx, policy, rule, input, opts)
		out.results = append(out.results, result)

		// Fail-fast: stop at first failure if configured
		if policy.Evaluation.FailFast && !result.Passed {
			out.failFast = true
			return out, nil
		}

		// maxRules: stop once the configured evaluation cap is reached
		if policy.Evaluation.MaxRules > 0 && len(out.results) >= policy.Evaluation.MaxRules {
			break
		}
	}

	return out, nil
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

// buildEvaluationErrorResult returns the synthetic failing result emitted when
// a policy cannot be evaluated at all. Like buildTimeoutResult it lives in the
// reserved system namespace and fails closed.
func buildEvaluationErrorResult(policy *CompiledPolicy, cause error) RuleResult {
	return RuleResult{
		PolicyNamespace: ReservedSystemNamespace,
		PolicyName:      SystemPolicyNameTimeout,
		RuleID:          RuleIDTimeout,
		RuleDescription: "Policy evaluation did not complete",
		Severity:        SeverityCritical,
		Passed:          false,
		Message: fmt.Sprintf("Evaluation of policy %s/%s failed: %v. The request was denied because the policy's rules did not run.",
			policy.Namespace, policy.Name, cause),
		Remediation: "Inspect the server logs for the underlying error and re-run `garmr validate` against this policy.",
		Bindings:    map[string]any{},
	}
}

// evaluateRule evaluates a single rule against input.
func (e *Engine) evaluateRule(ctx context.Context, policy *CompiledPolicy, rule CompiledRule, input cue.Value, opts EvaluateOptions) RuleResult {
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
		Passed:          true,
		Bindings:        make(map[string]any),
	}

	// No rule-level timeout check: the caller's loop tests ctx.Err() before
	// each rule and reports a policy-level timeout instead. Returning a
	// passing result here would fail open.

	// Evaluate the expression by unifying with input
	passed, bindings, msg := e.evaluateExpression(ctx, rule.Expression, input)
	result.Passed = passed
	result.Bindings = bindings

	if !passed {
		if rule.Message != "" {
			result.Message = e.interpolateMessage(rule.Message, bindings)
		} else if msg != "" {
			result.Message = msg
		} else {
			result.Message = fmt.Sprintf("Rule %s failed: %s", rule.ID, rule.Description)
		}
	}

	return result
}

// shouldEvaluateRule returns false if the rule should be skipped based on category/tag filters.
// Both policy-level and request-level filters are applied (both must pass).
func (e *Engine) shouldEvaluateRule(rule CompiledRule, policyConfig EvaluationConfig, opts EvaluateOptions) bool {
	// Check policy-level category filters
	if len(policyConfig.IncludeCategories) > 0 {
		if !stringInSlice(rule.Category, policyConfig.IncludeCategories) {
			return false
		}
	}
	if len(policyConfig.ExcludeCategories) > 0 {
		if stringInSlice(rule.Category, policyConfig.ExcludeCategories) {
			return false
		}
	}

	// Check policy-level tag filters
	if len(policyConfig.IncludeTags) > 0 {
		if !anyTagMatches(rule.Tags, policyConfig.IncludeTags) {
			return false
		}
	}
	if len(policyConfig.ExcludeTags) > 0 {
		if anyTagMatches(rule.Tags, policyConfig.ExcludeTags) {
			return false
		}
	}

	// Check request-level category filters
	if len(opts.IncludeCategories) > 0 {
		if !stringInSlice(rule.Category, opts.IncludeCategories) {
			return false
		}
	}
	if len(opts.ExcludeCategories) > 0 {
		if stringInSlice(rule.Category, opts.ExcludeCategories) {
			return false
		}
	}

	// Check request-level tag filters
	if len(opts.IncludeTags) > 0 {
		if !anyTagMatches(rule.Tags, opts.IncludeTags) {
			return false
		}
	}
	if len(opts.ExcludeTags) > 0 {
		if anyTagMatches(rule.Tags, opts.ExcludeTags) {
			return false
		}
	}

	return true
}

// matchesException checks if any non-expired exception matches the input.
func (e *Engine) matchesException(exceptions []ExceptionSpec, input map[string]any) bool {
	inputKind := getStringField(input, "kind")
	inputAPIGroup := getStringField(input, "apiVersion")
	inputName := getStringField(input, "metadata", "name")
	inputNamespace := getStringField(input, "metadata", "namespace")
	inputLabels := getMapField(input, "metadata", "labels")
	inputAnnotations := getMapField(input, "metadata", "annotations")

	for _, exc := range exceptions {
		// Check if exception has expired
		if exc.Expiry != nil && time.Now().After(*exc.Expiry) {
			continue
		}

		// Check if the exception's match selector applies to this input
		if e.selectorMatchesInput(exc.Match, inputKind, inputAPIGroup, inputName, inputNamespace, inputLabels, inputAnnotations) {
			return true
		}
	}

	return false
}

// interpolateMessage replaces template variables in a message.
func (e *Engine) interpolateMessage(msg string, bindings map[string]any) string {
	result := msg
	for k, v := range bindings {
		placeholder := fmt.Sprintf("{{.%s}}", k)
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", v))
	}
	return result
}

// buildNoMatchResult produces the synthetic RuleResult that accompanies a
// fail-closed DecisionDeny when zero policies matched. The message is
// tailored to the most specific cause the engine can identify from the
// request and the current policy set, so users get actionable remediation
// (typo'd namespace, missing policy name, or target-selector mismatch)
// instead of a generic deny.
func (e *Engine) buildNoMatchResult(rep *policyReplica, req *EvaluateRequest) RuleResult {
	const remediation = "Verify the namespace and policy names in your request, and run `garmr policy list` to inspect loaded policies."

	var message string
	switch {
	case len(rep.policies) == 0:
		message = "No policies are loaded on the server. Check the server's policy directory and ensure policies compiled successfully."
	case len(req.Policies) > 0:
		ns := req.Namespace
		if ns == "" {
			ns = "default"
		}
		var missing []string
		for _, name := range req.Policies {
			if _, ok := rep.policies[policyKey(ns, name)]; !ok {
				missing = append(missing, fmt.Sprintf("%s/%s", ns, name))
			}
		}
		if len(missing) > 0 {
			message = fmt.Sprintf("Policy %s not found. Run `garmr policy list` to see available policies.", strings.Join(missing, ", "))
		} else {
			message = fmt.Sprintf("Requested policies exist but none target this input (kind=%q apiVersion=%q). Check the target selectors on %s.",
				getStringField(req.Input, "kind"),
				getStringField(req.Input, "apiVersion"),
				strings.Join(req.Policies, ", "),
			)
		}
	case req.Namespace != "" && !namespaceHasPolicies(rep, req.Namespace):
		message = fmt.Sprintf("No policies found in namespace %q. Run `garmr policy list` to see available namespaces.", req.Namespace)
	default:
		message = fmt.Sprintf("No policy targets this input (kind=%q apiVersion=%q). Check resource selectors on your policies or the `kind` field of your input.",
			getStringField(req.Input, "kind"),
			getStringField(req.Input, "apiVersion"),
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

// namespaceHasPolicies reports whether any policy in the replica belongs to ns.
func namespaceHasPolicies(rep *policyReplica, ns string) bool {
	for _, p := range rep.policies {
		if p.Namespace == ns {
			return true
		}
	}
	return false
}
