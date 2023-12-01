package example

import (
	"context"

	"github.com/autom8ter/proto/gen/authenticate"

	"github.com/golang-jwt/jwt/v5"

	"github.com/autom8ter/protoc-gen-authenticate/authenticator"
	jwtAuth "github.com/autom8ter/protoc-gen-authenticate/jwt"
)

type ctxKey string

const (
	// CtxClaimsKey is the context key for storing the claims
	CtxClaimsKey ctxKey = "authenticate.claims"
)

// NewAuthentication returns a new authenticator that can be used in unary/stream interceptors
func NewAuthentication(environment string) (authenticator.AuthFunc, error) {
	auth, err := jwtAuth.NewJwtAuth(environment, CtxClaimsKey, map[string][]*authenticate.Config{
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
	})
	if err != nil {
		return nil, err
	}
	return auth.Authenticate, nil
}

// GetClaims returns the claims from a context
func GetClaims(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(CtxClaimsKey).(jwt.MapClaims)
	if !ok {
		return nil, false
	}
	return claims, true
}
