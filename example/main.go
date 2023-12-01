package main

import (
	"fmt"
	"net"

	"google.golang.org/grpc"

	"github.com/autom8ter/protoc-gen-authenticate/authenticator"
	"github.com/autom8ter/protoc-gen-authenticate/example/gen/example"
	"github.com/autom8ter/protoc-gen-authenticate/example/server"
)

func runServer() error {
	// create a new authenticator from the generated function(protoc-gen-authenticate)
	auth, err := example.NewAuthentication("TEST")
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
	example.RegisterPrivateServiceServer(srv, exampleServer)
	example.RegisterGoogleServiceServer(srv, exampleServer)
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
