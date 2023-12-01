package authenticator

import (
	"context"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthFunc is a function that authenticates a grpc request
type AuthFunc func(ctx context.Context) (context.Context, error)

// Authenticate implements the Authenticator interface
func (f AuthFunc) Authenticate(ctx context.Context) (context.Context, error) {
	return f(ctx)
}

// Authenticator is an interface that defines a grpc authenticator
type Authenticator interface {
	// Authenticate is a function that authenticates a grpc request
	Authenticate(ctx context.Context) (context.Context, error)
}

// UnaryServerInterceptor returns a new unary server interceptor that authenticates a grpc request
func UnaryServerInterceptor(auth Authenticator) grpc.UnaryServerInterceptor {
	return grpc_auth.UnaryServerInterceptor(auth.Authenticate)
}

// StreamServerInterceptor returns a new stream server interceptor that authenticates a grpc request
func StreamServerInterceptor(auth Authenticator) grpc.StreamServerInterceptor {
	return grpc_auth.StreamServerInterceptor(auth.Authenticate)
}

// AuthFromMD is a helper function that extracts an authorization token from a grpc metadata object
func AuthFromMD(ctx context.Context, scheme string) (string, error) {
	return grpc_auth.AuthFromMD(ctx, scheme)
}

// Chain returns a new Authenticator that chains multiple Authenticators together - the first Authenticator to successfully authenticate the request will be used
// if all Authenticators fail, the request will be rejected with a status code of codes.Unauthenticated
func Chain(auths ...Authenticator) Authenticator {
	return AuthFunc(func(ctx context.Context) (context.Context, error) {
		for _, auth := range auths {
			var err error
			ctx, err = auth.Authenticate(ctx)
			if err == nil {
				return ctx, nil
			}
		}
		return nil, status.Errorf(codes.Unauthenticated, "unauthenticated")
	})
}
