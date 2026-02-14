package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	policypb "github.com/infrashift/garmr/api/proto"
)

// policyManagementServiceImpl implements PolicyManagementServiceServer.
type policyManagementServiceImpl struct {
	policypb.UnimplementedPolicyManagementServiceServer
	srv *Server
}

func (m *policyManagementServiceImpl) ListPolicies(ctx context.Context, req *policypb.ListPoliciesRequest) (*policypb.ListPoliciesResponse, error) {
	policies := m.srv.engine.ListPolicies(req.GetNamespace())

	resp := &policypb.ListPoliciesResponse{}
	for _, p := range policies {
		resp.Policies = append(resp.Policies, enginePolicyToProtoInfo(p))
	}

	return resp, nil
}

func (m *policyManagementServiceImpl) GetPolicy(ctx context.Context, req *policypb.GetPolicyRequest) (*policypb.GetPolicyResponse, error) {
	p, err := m.srv.engine.GetPolicy(req.GetNamespace(), req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "policy %s/%s not found", req.GetNamespace(), req.GetName())
	}

	return &policypb.GetPolicyResponse{
		Name:      p.Name,
		Namespace: p.Namespace,
		Info:      enginePolicyToProtoInfo(p),
	}, nil
}

func (m *policyManagementServiceImpl) PutPolicy(ctx context.Context, req *policypb.PutPolicyRequest) (*policypb.PutPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "put policy is not yet implemented")
}

func (m *policyManagementServiceImpl) DeletePolicy(ctx context.Context, req *policypb.DeletePolicyRequest) (*policypb.DeletePolicyResponse, error) {
	deleted := m.srv.engine.DeletePolicy(req.GetNamespace(), req.GetName())
	return &policypb.DeletePolicyResponse{
		Deleted: deleted,
	}, nil
}

func (m *policyManagementServiceImpl) ReloadPolicies(ctx context.Context, req *policypb.ReloadPoliciesRequest) (*policypb.ReloadPoliciesResponse, error) {
	var count int
	var err error

	if m.srv.storageBackend != nil {
		count, err = m.srv.engine.ReloadPoliciesFromBackend(ctx, m.srv.storageBackend)
	} else if m.srv.config.PolicyDir != "" {
		count, err = m.srv.engine.ReloadPoliciesFromDir(ctx, m.srv.config.PolicyDir)
	} else {
		return nil, status.Error(codes.FailedPrecondition, "no policy source configured")
	}

	if err != nil {
		return &policypb.ReloadPoliciesResponse{
			Failed: 1,
			Errors: []string{err.Error()},
		}, nil
	}

	return &policypb.ReloadPoliciesResponse{
		Loaded: int32(count),
	}, nil
}
