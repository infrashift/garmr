package server

import (
	"context"
	"time"

	policypb "github.com/infrashift/garmr/api/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// healthServiceImpl implements HealthServiceServer.
type healthServiceImpl struct {
	policypb.UnimplementedHealthServiceServer
	srv *Server
}

func (h *healthServiceImpl) Health(ctx context.Context, req *policypb.HealthRequest) (*policypb.HealthResponse, error) {
	h.srv.mu.RLock()
	healthy := h.srv.ready
	h.srv.mu.RUnlock()

	return &policypb.HealthResponse{
		Healthy: healthy,
		Version: "0.1.0",
		Uptime:  timestamppb.New(time.Now().Add(-time.Since(h.srv.startTime))),
	}, nil
}

func (h *healthServiceImpl) Ready(ctx context.Context, req *policypb.ReadyRequest) (*policypb.ReadyResponse, error) {
	h.srv.mu.RLock()
	ready := h.srv.ready
	checks := make(map[string]bool, len(h.srv.checks))
	for k, v := range h.srv.checks {
		checks[k] = v
	}
	h.srv.mu.RUnlock()

	return &policypb.ReadyResponse{
		Ready:  ready,
		Checks: checks,
	}, nil
}
