package server

import (
	"context"
	"net"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	policypb "github.com/infrashift/garmr/api/proto"
	"github.com/infrashift/garmr/internal/engine"
)

const bufSize = 1024 * 1024

// setupGRPCTest creates an in-memory gRPC server+client for testing.
func setupGRPCTest(t *testing.T, apiKey string) (policypb.PolicyServiceClient, policypb.PolicyManagementServiceClient, policypb.HealthServiceClient, policypb.DataServiceClient, func()) {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	cfg := Config{
		APIKey: apiKey,
	}

	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.mu.Lock()
	srv.ready = true
	srv.checks["policies"] = true
	srv.mu.Unlock()

	lis := bufconn.Listen(bufSize)

	var opts []grpc.ServerOption
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			srv.recoveryUnaryInterceptor,
			srv.loggingUnaryInterceptor,
			srv.authUnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			srv.recoveryStreamInterceptor,
			srv.loggingStreamInterceptor,
			srv.authStreamInterceptor,
		),
	)

	gs := grpc.NewServer(opts...)
	policypb.RegisterPolicyServiceServer(gs, &policyServiceImpl{srv: srv})
	policypb.RegisterPolicyManagementServiceServer(gs, &policyManagementServiceImpl{srv: srv})
	policypb.RegisterHealthServiceServer(gs, &healthServiceImpl{srv: srv})
	policypb.RegisterDataServiceServer(gs, &dataServiceImpl{})

	go func() {
		if err := gs.Serve(lis); err != nil {
			// Server stopped
		}
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	cleanup := func() {
		conn.Close()
		gs.GracefulStop()
	}

	return policypb.NewPolicyServiceClient(conn),
		policypb.NewPolicyManagementServiceClient(conn),
		policypb.NewHealthServiceClient(conn),
		policypb.NewDataServiceClient(conn),
		cleanup
}

func ctxWithKey(key string) context.Context {
	md := metadata.Pairs("x-api-key", key)
	return metadata.NewOutgoingContext(context.Background(), md)
}

func ctxWithBearer(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(context.Background(), md)
}

// --- PolicyService tests ---

func TestGRPCEvaluateAllow(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	input, _ := structpb.NewStruct(map[string]any{
		"env": "prod",
	})

	resp, err := policyClient.Evaluate(context.Background(), &policypb.EvaluateRequest{
		Input:     input,
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision != policypb.Decision_DECISION_ALLOW {
		t.Errorf("expected ALLOW, got %v", resp.Decision)
	}
}

func TestGRPCEvaluateDeny(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	input, _ := structpb.NewStruct(map[string]any{
		"env": "dev",
	})

	resp, err := policyClient.Evaluate(context.Background(), &policypb.EvaluateRequest{
		Input:     input,
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if resp.Decision != policypb.Decision_DECISION_DENY {
		t.Errorf("expected DENY, got %v", resp.Decision)
	}
}

func TestGRPCEvaluateMissingInput(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	_, err := policyClient.Evaluate(context.Background(), &policypb.EvaluateRequest{})
	if err == nil {
		t.Fatal("expected error for missing input")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestGRPCValidateValid(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := policyClient.Validate(context.Background(), &policypb.ValidateRequest{
		Policy: testPolicyCUE,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true")
	}
}

func TestGRPCValidateInvalid(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := policyClient.Validate(context.Background(), &policypb.ValidateRequest{
		Policy: "this is not valid CUE {{{",
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false for invalid CUE")
	}
}

func TestGRPCCompileUnimplemented(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	_, err := policyClient.Compile(context.Background(), &policypb.CompileRequest{})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

// --- PolicyManagementService tests ---

func TestGRPCListPolicies(t *testing.T) {
	_, mgmtClient, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := mgmtClient.ListPolicies(context.Background(), &policypb.ListPoliciesRequest{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(resp.Policies) == 0 {
		t.Error("expected at least one policy")
	}
}

func TestGRPCGetPolicyFound(t *testing.T) {
	_, mgmtClient, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := mgmtClient.GetPolicy(context.Background(), &policypb.GetPolicyRequest{
		Name:      "test-policy",
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if resp.Name != "test-policy" {
		t.Errorf("expected test-policy, got %s", resp.Name)
	}
}

func TestGRPCGetPolicyNotFound(t *testing.T) {
	_, mgmtClient, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	_, err := mgmtClient.GetPolicy(context.Background(), &policypb.GetPolicyRequest{
		Name:      "nonexistent",
		Namespace: "default",
	})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestGRPCDeletePolicy(t *testing.T) {
	_, mgmtClient, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := mgmtClient.DeletePolicy(context.Background(), &policypb.DeletePolicyRequest{
		Name:      "test-policy",
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if !resp.Deleted {
		t.Error("expected deleted=true")
	}
}

func TestGRPCPutPolicyUnimplemented(t *testing.T) {
	_, mgmtClient, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	_, err := mgmtClient.PutPolicy(context.Background(), &policypb.PutPolicyRequest{
		Name:      "new-policy",
		Namespace: "default",
		Content:   testPolicyCUE,
	})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %v", err)
	}
}

func TestGRPCReloadPoliciesNoPolicyDir(t *testing.T) {
	_, mgmtClient, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	_, err := mgmtClient.ReloadPolicies(context.Background(), &policypb.ReloadPoliciesRequest{})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
}

// --- HealthService tests ---

func TestGRPCHealth(t *testing.T) {
	_, _, healthClient, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := healthClient.Health(context.Background(), &policypb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !resp.Healthy {
		t.Error("expected healthy=true")
	}
	if resp.Version != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %s", resp.Version)
	}
}

func TestGRPCReady(t *testing.T) {
	_, _, healthClient, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	resp, err := healthClient.Ready(context.Background(), &policypb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if !resp.Ready {
		t.Error("expected ready=true")
	}
}

// --- DataService tests ---

func TestGRPCDataUnimplemented(t *testing.T) {
	_, _, _, dataClient, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	_, err := dataClient.PutData(context.Background(), &policypb.PutDataRequest{Path: "test"})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("PutData: expected Unimplemented, got %v", st.Code())
	}

	_, err = dataClient.GetData(context.Background(), &policypb.GetDataRequest{Path: "test"})
	st, _ = status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("GetData: expected Unimplemented, got %v", st.Code())
	}

	_, err = dataClient.DeleteData(context.Background(), &policypb.DeleteDataRequest{Path: "test"})
	st, _ = status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("DeleteData: expected Unimplemented, got %v", st.Code())
	}
}

// --- Auth tests ---

func TestGRPCAuthNoKey(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "test-api-key")
	defer cleanup()

	input, _ := structpb.NewStruct(map[string]any{"env": "prod"})
	_, err := policyClient.Evaluate(context.Background(), &policypb.EvaluateRequest{
		Input: input,
	})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", err)
	}
}

func TestGRPCAuthValidKey(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "test-api-key")
	defer cleanup()

	input, _ := structpb.NewStruct(map[string]any{"env": "prod"})
	ctx := ctxWithKey("test-api-key")
	resp, err := policyClient.Evaluate(ctx, &policypb.EvaluateRequest{
		Input:     input,
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("Evaluate with valid key: %v", err)
	}
	if resp.Decision != policypb.Decision_DECISION_ALLOW {
		t.Errorf("expected ALLOW, got %v", resp.Decision)
	}
}

func TestGRPCAuthWrongKey(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "test-api-key")
	defer cleanup()

	input, _ := structpb.NewStruct(map[string]any{"env": "prod"})
	ctx := ctxWithKey("wrong-key")
	_, err := policyClient.Evaluate(ctx, &policypb.EvaluateRequest{
		Input: input,
	})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", err)
	}
}

func TestGRPCAuthHealthExempt(t *testing.T) {
	_, _, healthClient, _, cleanup := setupGRPCTest(t, "test-api-key")
	defer cleanup()

	// Health should be accessible without auth
	resp, err := healthClient.Health(context.Background(), &policypb.HealthRequest{})
	if err != nil {
		t.Fatalf("Health should be exempt from auth: %v", err)
	}
	if !resp.Healthy {
		t.Error("expected healthy=true")
	}
}

func TestGRPCAuthBearerToken(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "test-api-key")
	defer cleanup()

	input, _ := structpb.NewStruct(map[string]any{"env": "prod"})
	ctx := ctxWithBearer("test-api-key")
	resp, err := policyClient.Evaluate(ctx, &policypb.EvaluateRequest{
		Input:     input,
		Namespace: "default",
	})
	if err != nil {
		t.Fatalf("Evaluate with Bearer: %v", err)
	}
	if resp.Decision != policypb.Decision_DECISION_ALLOW {
		t.Errorf("expected ALLOW, got %v", resp.Decision)
	}
}

// --- EvaluateStream test ---

func TestGRPCEvaluateStream(t *testing.T) {
	policyClient, _, _, _, cleanup := setupGRPCTest(t, "")
	defer cleanup()

	stream, err := policyClient.EvaluateStream(context.Background())
	if err != nil {
		t.Fatalf("EvaluateStream: %v", err)
	}

	// Send allow input
	input1, _ := structpb.NewStruct(map[string]any{"env": "prod"})
	if err := stream.Send(&policypb.EvaluateRequest{Input: input1, Namespace: "default"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	resp1, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if resp1.Decision != policypb.Decision_DECISION_ALLOW {
		t.Errorf("expected ALLOW, got %v", resp1.Decision)
	}

	// Send deny input
	input2, _ := structpb.NewStruct(map[string]any{"env": "dev"})
	if err := stream.Send(&policypb.EvaluateRequest{Input: input2, Namespace: "default"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	resp2, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if resp2.Decision != policypb.Decision_DECISION_DENY {
		t.Errorf("expected DENY, got %v", resp2.Decision)
	}

	stream.CloseSend()
}
