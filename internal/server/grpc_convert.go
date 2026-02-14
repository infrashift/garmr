package server

import (
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	policypb "github.com/infrashift/garmr/api/proto"
	"github.com/infrashift/garmr/internal/engine"
)

// protoEvalRequestToEngine converts a proto EvaluateRequest to an engine EvaluateRequest.
func protoEvalRequestToEngine(req *policypb.EvaluateRequest) (*engine.EvaluateRequest, error) {
	var input map[string]any
	if req.GetInput() != nil {
		input = req.GetInput().AsMap()
	}

	opts := engine.EvaluateOptions{}
	if req.GetOptions() != nil {
		opts.Trace = req.Options.Trace
		opts.IncludePassed = req.Options.IncludePassed
		opts.Strict = req.Options.Strict
		opts.Instrument = req.Options.Instrument
		if req.Options.DryRun != nil {
			v := *req.Options.DryRun
			opts.DryRunOverride = &v
		}
	}

	return &engine.EvaluateRequest{
		Input:     input,
		Namespace: req.GetNamespace(),
		Policies:  req.GetPolicyNames(),
		Options:   opts,
	}, nil
}

// engineEvalResponseToProto converts an engine EvaluateResponse to a proto EvaluateResponse.
func engineEvalResponseToProto(resp *engine.EvaluateResponse) *policypb.EvaluateResponse {
	protoResp := &policypb.EvaluateResponse{
		Decision: engineDecisionToProto(resp.Decision),
	}

	for _, r := range resp.Results {
		protoResp.Results = append(protoResp.Results, engineRuleResultToProto(&r))
	}

	if resp.Metrics != nil {
		protoResp.Metrics = &policypb.Metrics{
			EvaluationTimeNs: resp.Metrics.EvaluationTimeNs,
			PoliciesEvaluated: int32(resp.Metrics.PoliciesEvaluated),
			RulesEvaluated:    int32(resp.Metrics.RulesEvaluated),
			CompileTimeNs:     resp.Metrics.CompileTimeNs,
		}
	}

	return protoResp
}

// engineDecisionToProto maps engine Decision to proto Decision.
func engineDecisionToProto(d engine.Decision) policypb.Decision {
	switch d {
	case engine.DecisionAllow:
		return policypb.Decision_DECISION_ALLOW
	case engine.DecisionDeny:
		return policypb.Decision_DECISION_DENY
	case engine.DecisionWarn:
		return policypb.Decision_DECISION_WARN
	default:
		return policypb.Decision_DECISION_UNSPECIFIED
	}
}

// engineSeverityToProto maps engine Severity to proto Severity.
func engineSeverityToProto(s engine.Severity) policypb.Severity {
	switch s {
	case engine.SeverityCritical:
		return policypb.Severity_SEVERITY_CRITICAL
	case engine.SeverityHigh:
		return policypb.Severity_SEVERITY_HIGH
	case engine.SeverityMedium:
		return policypb.Severity_SEVERITY_MEDIUM
	case engine.SeverityLow:
		return policypb.Severity_SEVERITY_LOW
	case engine.SeverityInfo:
		return policypb.Severity_SEVERITY_INFO
	default:
		return policypb.Severity_SEVERITY_UNSPECIFIED
	}
}

// engineRuleResultToProto converts a single engine RuleResult to proto.
func engineRuleResultToProto(r *engine.RuleResult) *policypb.RuleResult {
	pr := &policypb.RuleResult{
		PolicyName:      r.PolicyName,
		PolicyNamespace: r.PolicyNamespace,
		RuleId:          r.RuleID,
		RuleDescription: r.RuleDescription,
		Severity:        engineSeverityToProto(r.Severity),
		Passed:          r.Passed,
		Message:         r.Message,
	}

	pr.Bindings = bindingsToProto(r.Bindings)
	return pr
}

// bindingsToProto converts map[string]any bindings to proto Binding slice.
func bindingsToProto(bindings map[string]any) []*policypb.Binding {
	if len(bindings) == 0 {
		return nil
	}
	result := make([]*policypb.Binding, 0, len(bindings))
	for k, v := range bindings {
		val, err := structpb.NewValue(v)
		if err != nil {
			continue
		}
		result = append(result, &policypb.Binding{
			Name:  k,
			Value: val,
		})
	}
	return result
}

// enginePolicyToProtoInfo converts a CompiledPolicy to a proto PolicyInfo.
func enginePolicyToProtoInfo(p *engine.CompiledPolicy) *policypb.PolicyInfo {
	return &policypb.PolicyInfo{
		Name:      p.Name,
		Namespace: p.Namespace,
		RuleCount: int32(len(p.Rules)),
		LoadedAt:  timestamppb.New(p.LoadedAt),
		Hash:      p.Hash,
	}
}

// engineValidationErrorsToProto converts engine ValidationErrors to proto.
func engineValidationErrorsToProto(errs []engine.ValidationError) []*policypb.ValidationError {
	if len(errs) == 0 {
		return nil
	}
	result := make([]*policypb.ValidationError, len(errs))
	for i, e := range errs {
		result[i] = &policypb.ValidationError{
			Message: e.Message,
			Code:    e.Code,
		}
		if e.Line > 0 || e.Column > 0 {
			result[i].Position = &policypb.Position{
				Filename: e.Filename,
				Line:     int32(e.Line),
				Column:   int32(e.Column),
			}
		}
	}
	return result
}

// uptimeToTimestamp converts a start time to a proto Timestamp representing uptime start.
func uptimeToTimestamp(startTime time.Time) *timestamppb.Timestamp {
	return timestamppb.New(startTime)
}
