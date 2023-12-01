package authenticator

import (
	"context"

	`github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors`
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	`github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector`
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
func UnaryServerInterceptor(auth Authenticator, matchers ...selector.Matcher) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if len(matchers) == 0 {
			return grpc_auth.UnaryServerInterceptor(auth.Authenticate)(ctx, req, info, handler)
		}
		meta := interceptors.NewServerCallMeta(info.FullMethod, nil, req)
		for _, matcher := range matchers {
			if matcher.Match(ctx, meta) {
				return grpc_auth.UnaryServerInterceptor(auth.Authenticate)(ctx, req, info, handler)
			}
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a new stream server interceptor that authenticates a grpc request
// If no matchers are provided, the interceptor will attempt to authenticate all requests
// If matchers are provided, the interceptor will only attempt to authenticate requests if at least one matcher matches
func StreamServerInterceptor(auth Authenticator, matchers ...selector.Matcher) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if len(matchers) == 0 {
			return grpc_auth.StreamServerInterceptor(auth.Authenticate)(srv, ss, info, handler)
		}
		meta := interceptors.NewServerCallMeta(info.FullMethod, info, nil)
		for _, matcher := range matchers {
			if matcher.Match(ss.Context(), meta) {
				return grpc_auth.StreamServerInterceptor(auth.Authenticate)(srv, ss, info, handler)
			}
		}
		return handler(srv, ss)
	}
}

// AuthFromMD is a helper function that extracts an authorization token from a grpc metadata object (same as github.com/grpc-ecosystem/go-grpc-middleware/auth.AuthFromMD)
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
