package main

import (
	"context"
	"fmt"
	"net"

	jwt2 "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"

	"github.com/autom8ter/protoc-gen-authenticate/authenticator"
	examplev1 "github.com/autom8ter/protoc-gen-authenticate/example/gen/example/v1"
	"github.com/autom8ter/protoc-gen-authenticate/example/server"
	"github.com/autom8ter/protoc-gen-authenticate/jwt"
)

func runServer() error {
	var ctxKey = "user"
	// create a new authenticator from the generated function(protoc-gen-authenticate)
	auth, err := examplev1.NewAuthentication("TEST", jwt.WithClaimsToContext(func(ctx context.Context, claims jwt2.MapClaims) (context.Context, error) {
		return context.WithValue(ctx, ctxKey, claims), nil
	}))
	if err != nil {
		return err
	}
	// create a new grpc server with the authorizer interceptors
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(
			authenticator.UnaryServerInterceptor(auth),
		),
		grpc.StreamInterceptor(
			authenticator.StreamServerInterceptor(auth),
		),
	)
	exampleServer := &server.ExampleServer{}
	// register the example service
	examplev1.RegisterPrivateServiceServer(srv, exampleServer)
	examplev1.RegisterGoogleServiceServer(srv, exampleServer)
	lis, err := net.Listen("tcp", ":10042")
	if err != nil {
		return err
	}
	defer lis.Close()
	fmt.Println("starting server on :10042")
	// start the server
	if err := srv.Serve(lis); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := runServer(); err != nil {
		panic(err)
	}
}
