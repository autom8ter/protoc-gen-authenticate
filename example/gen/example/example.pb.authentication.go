package example

import (
	"github.com/autom8ter/proto/gen/authenticate"

	"github.com/autom8ter/protoc-gen-authenticate/authenticator"
	jwtAuth "github.com/autom8ter/protoc-gen-authenticate/jwt"
)

// NewAuthentication returns a new authenticator that can be used in unary/stream interceptors
// The authenticator will use the claimsToContext function to add claims to the context if the request is authenticated
func NewAuthentication(environment string, opts ...jwtAuth.Option) (authenticator.AuthFunc, error) {
	auth, err := jwtAuth.NewJwtAuth(environment, map[string][]*authenticate.Config{
		"example.GoogleService": {
			{
				Environment: "TEST",
				WhitelistMethods: []string{
					"Login",
				},
				Providers: []*authenticate.Provider{
					{
						Name: "google",
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
		"example.PrivateService": {
			{
				Environment: "TEST",
				WhitelistMethods: []string{
					"Unauthenticated",
				},
				Providers: []*authenticate.Provider{
					{
						Name: "custom",
						Provider: &authenticate.Provider_Jwt{
							Jwt: &authenticate.JwtProvider{
								Issuer:        "",
								Audience:      "",
								Algorithm:     authenticate.Algorithm_HS256,
								JwksUri:       "",
								SecretEnv:     "JWT_DEV_SECRET",
								RequireClaims: []string{},
							},
						},
					},
				},
			},
			{
				Environment: "PROD",
				WhitelistMethods: []string{
					"Unauthenticated",
				},
				Providers: []*authenticate.Provider{
					{
						Name: "custom",
						Provider: &authenticate.Provider_Jwt{
							Jwt: &authenticate.JwtProvider{
								Issuer:        "",
								Audience:      "",
								Algorithm:     authenticate.Algorithm_HS256,
								JwksUri:       "",
								SecretEnv:     "JWT_PROD_SECRET",
								RequireClaims: []string{},
							},
						},
					},
				},
			},
		},
	}, opts...)
	if err != nil {
		return nil, err
	}
	return auth.Authenticate, nil
}
