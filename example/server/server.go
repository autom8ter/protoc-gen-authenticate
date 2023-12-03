package server

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/autom8ter/protoc-gen-authenticate/example/gen/example/v1"
)

type ExampleServer struct {
	examplev1.UnimplementedGoogleServiceServer
	examplev1.UnimplementedPrivateServiceServer
}

func (e *ExampleServer) RequireAuthentication(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (e *ExampleServer) Unauthenticated(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (e *ExampleServer) Login(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (e *ExampleServer) Logout(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
