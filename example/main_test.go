package main

import (
	"context"
	"testing"
	"time"

	jwt2 "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/autom8ter/protoc-gen-authenticate/example/gen/example"
	"github.com/autom8ter/protoc-gen-authenticate/jwt"
)

var secret = "test-secret"

func Test(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := runServer(); err != nil {
			panic(err)
		}
	}()
	// wait for server to start
	time.Sleep(1 * time.Second)
	// create a token to send to the server
	token, err := jwt.Sign(ctx, jwt2.MapClaims{
		"sub":  "1234567890",
		"iss":  "test",
		"aud":  "test",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
		"nbf":  time.Now().Unix(),
		"name": "John Doe",
	}, secret, jwt2.SigningMethodHS256)
	if err != nil {
		panic(err)
	}
	conn, err := grpc.Dial(":10042", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	privateClient := example.NewPrivateServiceClient(conn)
	if _, err := privateClient.Unauthenticated(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("failed to call Unauthenticated: %v", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	if _, err := privateClient.RequireAuthentication(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("failed to call RequireAuthentication: %v", err)
	}

}
