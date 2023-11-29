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

- [x] Compatible with grpc-middleware authentication interceptors
- [x] Highly configurable JWT authentication
- [x] Supports multiple authentication providers
- [x] Support for Remote JWKS (JSON Web Key Set) endpoints
- [x] Support for different providers based on environment variables(GRPC_AUTH)

## Installation

The plugin can be installed with the following command:

```bash
    go install github.com/autom8ter/protoc-gen-authenticate
```

## Code Generation

buf.gen.yaml example:

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

## Example

See [example](example) for the full example.
