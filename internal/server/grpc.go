package server

import (
	"crypto/tls"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	policypb "github.com/infrashift/garmr/api/proto"
)

// startGRPC starts the gRPC server.
func (s *Server) startGRPC() error {
	lis, err := net.Listen("tcp", s.config.GRPCAddr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}

	var opts []grpc.ServerOption

	// TLS
	if s.config.EnableTLS && s.config.TLSCert != "" && s.config.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.config.TLSCert, s.config.TLSKey)
		if err != nil {
			return fmt.Errorf("loading TLS cert for gRPC: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Max receive size
	if s.config.MaxRecvSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(s.config.MaxRecvSize))
	}

	// Interceptor chains
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			s.recoveryUnaryInterceptor,
			s.loggingUnaryInterceptor,
			s.authUnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			s.recoveryStreamInterceptor,
			s.loggingStreamInterceptor,
			s.authStreamInterceptor,
		),
	)

	s.grpcServer = grpc.NewServer(opts...)

	// Register services
	policypb.RegisterPolicyServiceServer(s.grpcServer, &policyServiceImpl{srv: s})
	policypb.RegisterPolicyManagementServiceServer(s.grpcServer, &policyManagementServiceImpl{srv: s})
	policypb.RegisterHealthServiceServer(s.grpcServer, &healthServiceImpl{srv: s})
	policypb.RegisterDataServiceServer(s.grpcServer, &dataServiceImpl{})

	// Enable reflection for tools like grpcurl
	reflection.Register(s.grpcServer)

	s.logger.Info("starting gRPC server", zap.String("addr", s.config.GRPCAddr))
	return s.grpcServer.Serve(lis)
}

// stopGRPC gracefully stops the gRPC server.
func (s *Server) stopGRPC() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}
