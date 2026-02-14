package server

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	policypb "github.com/infrashift/garmr/api/proto"
)

// policyServiceImpl implements PolicyServiceServer.
type policyServiceImpl struct {
	policypb.UnimplementedPolicyServiceServer
	srv *Server
}

func (p *policyServiceImpl) Evaluate(ctx context.Context, req *policypb.EvaluateRequest) (*policypb.EvaluateResponse, error) {
	startTime := time.Now()
	requestID := uuid.New().String()

	engineReq, err := protoEvalRequestToEngine(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	if engineReq.Input == nil {
		return nil, status.Error(codes.InvalidArgument, "input is required")
	}

	result, err := p.srv.engine.Evaluate(ctx, engineReq)
	if err != nil {
		p.srv.logger.Error("grpc evaluation failed", zap.Error(err))
		return nil, status.Error(codes.Internal, "evaluation failed")
	}

	// Record metrics
	p.srv.obs.Metrics().RecordEvaluation(
		"",
		req.GetNamespace(),
		decisionToString(result.Decision),
		"",
		time.Since(startTime),
	)

	// Audit log
	auditGRPCEvaluation(p.srv, ctx, requestID, req, result, startTime)

	return engineEvalResponseToProto(result), nil
}

func (p *policyServiceImpl) EvaluateStream(stream grpc.BidiStreamingServer[policypb.EvaluateRequest, policypb.EvaluateResponse]) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		resp, err := p.Evaluate(stream.Context(), req)
		if err != nil {
			return err
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (p *policyServiceImpl) Validate(ctx context.Context, req *policypb.ValidateRequest) (*policypb.ValidateResponse, error) {
	if req.GetPolicy() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy content is required")
	}

	errs, warnings := p.srv.engine.Validate(req.GetPolicy())

	return &policypb.ValidateResponse{
		Valid:    len(errs) == 0,
		Errors:   engineValidationErrorsToProto(errs),
		Warnings: engineValidationErrorsToProto(warnings),
	}, nil
}

func (p *policyServiceImpl) Compile(ctx context.Context, req *policypb.CompileRequest) (*policypb.CompileResponse, error) {
	return nil, status.Error(codes.Unimplemented, "compile is not yet implemented")
}

// auditGRPCEvaluation logs a gRPC evaluation to the audit log.
func auditGRPCEvaluation(s *Server, ctx context.Context, requestID string, req *policypb.EvaluateRequest, result interface{ }, startTime time.Time) {
	if s.auditLogger == nil {
		return
	}

	sourceIP := ""
	if p, ok := peer.FromContext(ctx); ok {
		sourceIP = p.Addr.String()
	}

	type evalResult interface {
		GetDecision() policypb.Decision
	}
	// We have the engine result, but since we already converted to proto, let's extract
	// fields we need directly
	s.auditLogger.Info("decision",
		"request_id", requestID,
		"timestamp", time.Now().UTC().Format(time.RFC3339Nano),
		"transport", "grpc",
		"namespace", req.GetNamespace(),
		"source_ip", sourceIP,
	)
}
