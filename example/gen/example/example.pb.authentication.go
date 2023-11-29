package example

import (
	"github.com/autom8ter/proto/gen/authenticate"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"

	"github.com/autom8ter/protoc-gen-authenticate/jwt"
)

type ctxKey string

const (
	// CtxClaimsKey is the context key for storing the claims
	CtxClaimsKey ctxKey = "authenticate.claims"
)

// NewAuthentication returns a new authentication interceptor
func NewAuthentication() (grpc_auth.AuthFunc, error) {
	auth, err := jwt.NewJwtAuth(CtxClaimsKey, map[string][]*authenticate.Config{
		"GoogleService": {
			{
				RequireEnv: "",
				Providers: []*authenticate.Provider{
					{
						Provider: &authenticate.Provider_Jwt{
							Jwt: &authenticate.JwtProvider{
								Issuer:    "https://accounts.google.com",
								Audience:  "https://example.com",
								Algorithm: authenticate.Algorithm_RS256,
								JwksUri:   "https://www.googleapis.com/oauth2/v3/certs",
								SecretEnv: "",
								RequireClaims: []string{
									"email_verified",
									"email",
								},
							},
						},
					},
				},
			},
		},
		"PrivateService": {
			{
				RequireEnv: "DEV",
				Providers: []*authenticate.Provider{
					{
						Provider: &authenticate.Provider_Jwt{
							Jwt: &authenticate.JwtProvider{
								Issuer:        "",
								Audience:      "",
								Algorithm:     authenticate.Algorithm_RS256,
								JwksUri:       "",
								SecretEnv:     "JWT_DEV_SECRET",
								RequireClaims: []string{},
							},
						},
					},
				},
			},
			{
				RequireEnv: "PROD",
				Providers: []*authenticate.Provider{
					{
						Provider: &authenticate.Provider_Jwt{
							Jwt: &authenticate.JwtProvider{
								Issuer:        "",
								Audience:      "",
								Algorithm:     authenticate.Algorithm_RS256,
								JwksUri:       "",
								SecretEnv:     "JWT_PROD_SECRET",
								RequireClaims: []string{},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return auth.Verify, nil
}
