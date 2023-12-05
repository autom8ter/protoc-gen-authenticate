# protoc-gen-authenticate 🛡️

![GoDoc](https://godoc.org/github.com/autom8ter/protoc-gen-authenticate?status.svg)

**protoc-gen-authenticate** is an innovative protoc plugin and library 🌟 designed to simplify and secure gRPC request
authentication.
It seamlessly integrates authentication providers directly within your proto files 📝, reducing the need to clutter your
application code with complex authentication logic.
Perfect for developers 👨‍💻👩‍💻 looking to streamline their security workflows in gRPC applications.
In this README, you'll find easy installation instructions 📥, examples 💡, and all you need to harness the power of
expression-based rules for robust and efficient request handling 💼.

## Features

- [x] Generated code can be used with Unary and Stream interceptors in `github.com/autom8ter/protoc-gen-authenticate/authenticator`
- [x] Highly configurable JWT authentication
- [x] Supports multiple authentication providers
- [x] Support for Remote JWKS (JSON Web Key Set) endpoints
- [x] Support for different providers based on environment

## Installation

The plugin can be installed with the following command:

```bash
    go install github.com/autom8ter/protoc-gen-authenticate
```

## Code Generation

Add the proto file to your protobuf directory(usually `proto/`):

    mkdir -p proto/authenticate
    curl -sSL https://raw.githubusercontent.com/autom8ter/proto/master/proto/authenticate/authenticate.proto > proto/authenticate/authenticate.proto

You can then import the proto file in your proto files:

```proto
import "authenticate/authenticate.proto";
```

To generate the code, you can add the following to your `buf.gen.yaml` file:
```yaml
version: v1
plugins:
  - plugin: buf.build/protocolbuffers/go
    out: gen
    opt: paths=source_relative
  - plugin: buf.build/grpc/go
    out: gen
    opt:
      - paths=source_relative
  - plugin: authenticate
    out: gen
    opt:
      - paths=source_relative
```
See [buf.build](https://buf.build/docs/ecosystem/cli-overview) for more information on how to use `buf` to generate code.


## Example

```proto
// GoogleService service is an example of how to authenticate with Google's OAuth2 service
service GoogleService {
  option (authenticate.config) = {
    environment: "TEST"
    providers: [{
      name: "google",
      jwt: {
        algorithm: RS256,
        jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
        issuer: "https://accounts.google.com",
        audience: "https://example.com",
        require_claims: ["email_verified", "email"],
      },
    }]
    whitelist_methods: ["Login"]
  };
  rpc Login(google.protobuf.Empty) returns (google.protobuf.Empty);
  rpc Logout(google.protobuf.Empty) returns (google.protobuf.Empty);
}

service PrivateService {
  option (authenticate.config) = {
    environment: "TEST"
    whitelist_methods: ["Unauthenticated"]
    providers: [
      {
        name: "custom",
        jwt: {
          algorithm: HS256,
          secret_env: "JWT_DEV_SECRET",
        }
      }
    ]
  };
  option (authenticate.config) = {
    // only enabled when GRPC_AUTH=PROD env var is set
    environment: "PROD"
    whitelist_methods: ["Unauthenticated"]
    providers: [{
      name: "custom",
      jwt: {
        algorithm: HS256,
        secret_env: "JWT_PROD_SECRET",
      }
    }]
  };
  rpc RequireAuthentication(google.protobuf.Empty) returns (google.protobuf.Empty);
  rpc Unauthenticated(google.protobuf.Empty) returns (google.protobuf.Empty);
}
```

```go
    // create a new authenticator from the generated function(protoc-gen-authenticate)
	// jwt.WithClaimsToContext is an optional option that allows you to add claims to the context so that they can be extracted in your application code
	// normally, you would use this to lookup the user in your database and add the user to the context
	auth, err := example.NewAuthentication("TEST", jwt.WithClaimsToContext(func(ctx context.Context, claims jwt2.MapClaims) (context.Context, error) {
        return context.WithValue(ctx, ctxKey, claims), nil
    }))
	if err != nil {
		return err
	}
	// create a new grpc server with the authorizer interceptors
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpc_auth.UnaryServerInterceptor(auth),
		),
		grpc.StreamInterceptor(
			grpc_auth.StreamServerInterceptor(auth),
		),
	)
```

See [example](example) for the full example.
