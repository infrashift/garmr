package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"go.uber.org/zap"
)

// Evaluate evaluates input against loaded policies.
func (e *Engine) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Track active evaluations for metrics
	e.obs.Metrics().IncActiveEvaluations()
	defer e.obs.Metrics().DecActiveEvaluations()

	// Borrow a CUE context from the pool for this evaluation.
	// This ensures each concurrent evaluation has its own context,
	// avoiding thread-safety issues with shared cue.Context usage.
	cueCtx := e.ctxPool.get()
	defer e.ctxPool.put(cueCtx)

	// Store the pooled CUE context in the Go context so all downstream
	// evaluation methods can access it without signature changes.
	ctx = withCueContext(ctx, cueCtx)

	start := time.Now()
	resp := &EvaluateResponse{
		Decision: DecisionAllow,
		Metrics:  &Metrics{},
	}

	if req.Options.Trace {
		resp.Trace = []TraceEvent{}
	}

	// Convert input to CUE value using pooled context
	inputVal := cueCtx.Encode(req.Input)
	if inputVal.Err() != nil {
		return nil, fmt.Errorf("%w: encoding input: %v", ErrInvalidInput, inputVal.Err())
	}

	// Find applicable policies
	policies := e.findApplicablePolicies(req)
	resp.Metrics.PoliciesEvaluated = len(policies)

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

	// Count total rules in scope for fail-fast metadata
	totalRulesInScope := 0
	for _, p := range policies {
		totalRulesInScope += len(p.Rules)
	}
	rulesEvaluated := 0

	// Evaluate each policy
	for _, policy := range policies {
		results, failFastTriggered, err := e.evaluatePolicy(ctx, policy, inputVal, req)
		if err != nil {
			e.logger.Error("policy evaluation failed",
				zap.String("policy", policy.Name),
				zap.Error(err),
			)
			continue
		}

		rulesEvaluated += len(results)
		resp.Metrics.RulesEvaluated += len(results)

		// Determine dry run mode
		isDryRun := false
		if req.Options.DryRunOverride != nil {
			isDryRun = *req.Options.DryRunOverride
		} else {
			isDryRun = policy.Enforcement.DryRun
		}

		for _, result := range results {
			if !result.Passed {
				// Record violation metric
				e.obs.Metrics().RecordViolation(policy.Name, policy.Namespace, result.RuleID, string(result.Severity))

				// Update decision based on severity and enforcement
				switch policy.Enforcement.Action {
				case "deny":
					resp.Decision = DecisionDeny
				case "warn":
					if resp.Decision != DecisionDeny {
						resp.Decision = DecisionWarn
					}
				}

				// Dry run: downgrade deny to warn and annotate the message
				if isDryRun {
					if resp.Decision == DecisionDeny {
						resp.Decision = DecisionWarn
					}
					result.Message = "[DRY RUN] " + result.Message
				}
			}

			// Include result based on options
			if !result.Passed || req.Options.IncludePassed {
				resp.Results = append(resp.Results, result)
			}
		}

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

	resp.Metrics.EvaluationTimeNs = time.Since(start).Nanoseconds()

	// Record evaluation metric
	e.obs.Metrics().RecordEvaluation(
		"",                       // policy name (we evaluate multiple)
		req.Namespace,            // namespace
		string(resp.Decision),    // decision
		"",                       // environment
		time.Since(start),        // duration
	)

	return resp, nil
}

// findApplicablePolicies returns policies that match the request.
func (e *Engine) findApplicablePolicies(req *EvaluateRequest) []*CompiledPolicy {
	var result []*CompiledPolicy

	// If specific policies requested, return only those
	if len(req.Policies) > 0 {
		for _, name := range req.Policies {
			ns := req.Namespace
			if ns == "" {
				ns = "default"
			}
			key := policyKey(ns, name)
			if p, ok := e.policies[key]; ok {
				if e.policyMatchesInput(p, req.Input) {
					result = append(result, p)
				}
			}
		}
		return result
	}

	// Otherwise, return all policies in namespace that match the input
	for _, p := range e.policies {
		if req.Namespace == "" || p.Namespace == req.Namespace {
			if e.policyMatchesInput(p, req.Input) {
				result = append(result, p)
			}
		}
	}

	return result
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

	// Check if any target selector matches
	for _, selector := range policy.Target.Resources {
		if e.selectorMatchesInput(selector, inputKind, inputAPIGroup, inputName, inputNamespace, inputLabels) {
			return true
		}
	}

	return false
}

// selectorMatchesInput checks if a resource selector matches the input.
func (e *Engine) selectorMatchesInput(selector ResourceSelector, kind, apiGroup, name, namespace string, labels map[string]string) bool {
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

	return true
}

// evaluatePolicy evaluates a single policy against input.
// Returns results, whether fail-fast was triggered, and any error.
func (e *Engine) evaluatePolicy(ctx context.Context, policy *CompiledPolicy, input cue.Value, req *EvaluateRequest) ([]RuleResult, bool, error) {
	var results []RuleResult
	opts := req.Options

	// Check if any exception matches the input, skip evaluation if so
	if len(policy.Enforcement.Exceptions) > 0 {
		if e.matchesException(policy.Enforcement.Exceptions, req.Input) {
			return results, false, nil
		}
	}

	for _, rule := range policy.Rules {
		// Category/tag filtering: skip rules that don't match filters
		if !e.shouldEvaluateRule(rule, policy.Evaluation, opts) {
			continue
		}

		// Timeout check: if the context has been cancelled/timed out, stop evaluating
		if ctx.Err() != nil {
			result := RuleResult{
				PolicyName:      policy.Name,
				PolicyNamespace: policy.Namespace,
				RuleID:          rule.ID,
				RuleDescription: rule.Description,
				Severity:        rule.Severity,
				Passed:          true, // don't penalize on timeout
				Message:         "evaluation timed out",
				Bindings:        make(map[string]any),
			}
			results = append(results, result)
			break
		}

		result := e.evaluateRule(ctx, policy, rule, input, opts)
		results = append(results, result)

		// Fail-fast: stop at first failure if configured
		if policy.Evaluation.FailFast && !result.Passed {
			return results, true, nil
		}
	}

	return results, false, nil
}

// evaluateRule evaluates a single rule against input.
func (e *Engine) evaluateRule(ctx context.Context, policy *CompiledPolicy, rule CompiledRule, input cue.Value, opts EvaluateOptions) RuleResult {
	result := RuleResult{
		PolicyName:      policy.Name,
		PolicyNamespace: policy.Namespace,
		RuleID:          rule.ID,
		RuleDescription: rule.Description,
		Severity:        rule.Severity,
		Passed:          true,
		Bindings:        make(map[string]any),
	}

	// Timeout check at rule level
	if ctx.Err() != nil {
		result.Passed = true // don't penalize on timeout
		result.Message = "evaluation timed out"
		return result
	}

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

	for _, exc := range exceptions {
		// Check if exception has expired
		if exc.Expiry != nil && time.Now().After(*exc.Expiry) {
			continue
		}

		// Check if the exception's match selector applies to this input
		if e.selectorMatchesInput(exc.Match, inputKind, inputAPIGroup, inputName, inputNamespace, inputLabels) {
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
