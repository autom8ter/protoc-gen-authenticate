package server

import (
	"github.com/autom8ter/protoc-gen-authenticate/example/gen/example"
)

type exampleServer struct {
	example.UnimplementedPrivateServiceServer
	example.UnimplementedGoogleServiceServer
}

func NewExampleServer() (example.GoogleServiceServer, example.PrivateServiceServer) {
	return &exampleServer{}, &exampleServer{}
}
