package server

import (
	"context"
	"crypto/subtle"
	"runtime/debug"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authUnaryInterceptor provides API key authentication for unary RPCs.
func (s *Server) authUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := s.authenticateGRPC(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// authStreamInterceptor provides API key authentication for streaming RPCs.
func (s *Server) authStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.authenticateGRPC(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

// authenticateGRPC checks the API key from gRPC metadata.
func (s *Server) authenticateGRPC(ctx context.Context, method string) error {
	// Skip auth if no API key configured
	if s.config.APIKey == "" {
		return nil
	}

	// Exempt health/ready RPCs
	if strings.HasSuffix(method, "/Health") || strings.HasSuffix(method, "/Ready") {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Check x-api-key header
	var providedKey string
	if keys := md.Get("x-api-key"); len(keys) > 0 {
		providedKey = keys[0]
	}

	// Fallback to authorization: Bearer
	if providedKey == "" {
		if auths := md.Get("authorization"); len(auths) > 0 {
			if strings.HasPrefix(auths[0], "Bearer ") {
				providedKey = strings.TrimPrefix(auths[0], "Bearer ")
			}
		}
	}

	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(s.config.APIKey)) == 0 {
		return status.Error(codes.Unauthenticated, "invalid or missing API key")
	}

	return nil
}

// loggingUnaryInterceptor logs gRPC unary calls.
func (s *Server) loggingUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	duration := time.Since(start)

	code := codes.OK
	if err != nil {
		if st, ok := status.FromError(err); ok {
			code = st.Code()
		}
	}

	s.logger.Info("grpc unary",
		zap.String("method", info.FullMethod),
		zap.String("code", code.String()),
		zap.Duration("duration", duration),
	)
	return resp, err
}

// loggingStreamInterceptor logs gRPC streaming calls.
func (s *Server) loggingStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	start := time.Now()
	err := handler(srv, ss)
	duration := time.Since(start)

	code := codes.OK
	if err != nil {
		if st, ok := status.FromError(err); ok {
			code = st.Code()
		}
	}

	s.logger.Info("grpc stream",
		zap.String("method", info.FullMethod),
		zap.String("code", code.String()),
		zap.Duration("duration", duration),
	)
	return err
}

// recoveryUnaryInterceptor catches panics in unary RPCs.
func (s *Server) recoveryUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("grpc panic recovered",
				zap.String("method", info.FullMethod),
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())),
			)
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, req)
}

// recoveryStreamInterceptor catches panics in streaming RPCs.
func (s *Server) recoveryStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("grpc panic recovered",
				zap.String("method", info.FullMethod),
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())),
			)
			err = status.Errorf(codes.Internal, "internal server error")
		}
	}()
	return handler(srv, ss)
}
