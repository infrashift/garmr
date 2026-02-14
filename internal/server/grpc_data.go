package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	policypb "github.com/infrashift/garmr/api/proto"
)

// dataServiceImpl implements DataServiceServer.
type dataServiceImpl struct {
	policypb.UnimplementedDataServiceServer
}

func (d *dataServiceImpl) PutData(ctx context.Context, req *policypb.PutDataRequest) (*policypb.PutDataResponse, error) {
	return nil, status.Error(codes.Unimplemented, "data store is not yet implemented")
}

func (d *dataServiceImpl) GetData(ctx context.Context, req *policypb.GetDataRequest) (*policypb.GetDataResponse, error) {
	return nil, status.Error(codes.Unimplemented, "data store is not yet implemented")
}

func (d *dataServiceImpl) DeleteData(ctx context.Context, req *policypb.DeleteDataRequest) (*policypb.DeleteDataResponse, error) {
	return nil, status.Error(codes.Unimplemented, "data store is not yet implemented")
}
