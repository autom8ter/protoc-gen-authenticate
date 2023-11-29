package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/autom8ter/protoc-gen-authenticate/example/gen/example"
)

func Test(t *testing.T) {
	go func() {
		if err := runServer(); err != nil {
			panic(err)
		}
	}()
	// wait for server to start
	time.Sleep(1 * time.Second)
	conn, err := grpc.Dial(":10042", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	googClient := example.NewGoogleServiceClient(conn)
	privateClient := example.NewPrivateServiceClient(conn)

	{

		if _, err := googClient.Login(context.Background(), &emptypb.Empty{}); err == nil {
			t.Fatalf("expected error, got nil")
		} else {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("expected error code %v, got %v", codes.PermissionDenied, status.Code(err))
			}
		}
		if _, err := googClient.Logout(context.Background(), &emptypb.Empty{}); err == nil {
			t.Fatalf("expected error, got nil")
		} else {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("expected error code %v, got %v", codes.PermissionDenied, status.Code(err))
			}
		}
	}
	{
		if _, err := privateClient.Unauthenticated(context.Background(), &emptypb.Empty{}); err != nil {
			t.Fatalf("failed to call RequestMatch: %v", err)
		}
		if _, err := privateClient.RequireAuthentication(context.Background(), &emptypb.Empty{}); err != nil {
			t.Fatalf("failed to call RequestMatch: %v", err)
		}
	}
}
