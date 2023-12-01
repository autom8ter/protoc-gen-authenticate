package jwt_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/autom8ter/proto/gen/authenticate"
	jwt2 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/autom8ter/protoc-gen-authenticate/jwt"
)

type fixture struct {
	name         string
	environment  string
	method       string // method to call
	config       map[string][]*authenticate.Config
	expectError  bool
	getToken     func(t *testing.T, ctx context.Context) string
	expectClaims func(t *testing.T, claims jwt2.MapClaims)
}

func TestJwtAuth_Authenticate(t *testing.T) {
	var fixtures = []*fixture{
		{
			environment: "TEST",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audience",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectClaims: func(t *testing.T, claims jwt2.MapClaims) {
				require.Equal(t, "1234567890", claims["sub"])
				require.Equal(t, "John Doe", claims["name"])
				require.Equal(t, "test-issuer", claims["iss"])
				require.Equal(t, "test-audience", claims["aud"])
			},
		},
		{
			environment: "PROD",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audience",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			environment: "PROD",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audience",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud", "email"},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name:        "wrong secret env",
			environment: "TEST",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audience",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET_2",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name:        "invalid issuer",
			environment: "TEST",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issur",
										Audience:      "test-audience",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name:        "invalid audience",
			environment: "TEST",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audence",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name:        "whitelist method",
			environment: "TEST",
			method:      "/example.PrivateService/Unauthenticated",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: []string{"Unauthenticated"},
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-isser",
										Audience:      "test-audence",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "pass multiple configs",
			environment: "TEST",
			method:      "/example.PrivateService/RequireAuthentication",
			getToken: func(t *testing.T, ctx context.Context) string {
				var secret = "test-secret"
				os.Setenv("JWT_SECRET", secret)
				token, err := jwt.Sign(ctx, jwt2.MapClaims{
					"sub":  "1234567890",
					"name": "John Doe",
					"iat":  time.Now().Unix(),
					"exp":  time.Now().Add(time.Hour).Unix(),
					"iss":  "test-issuer",
					"aud":  "test-audience",
				}, secret, jwt2.SigningMethodHS256)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
				return token
			},
			config: map[string][]*authenticate.Config{
				"example.PrivateService": {
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audence",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
					{
						Environment:      "TEST",
						WhitelistMethods: nil,
						Providers: []*authenticate.Provider{
							{
								Provider: &authenticate.Provider_Jwt{
									Jwt: &authenticate.JwtProvider{
										Issuer:        "test-issuer",
										Audience:      "test-audience",
										Algorithm:     authenticate.Algorithm_HS256,
										SecretEnv:     "JWT_SECRET",
										RequireClaims: []string{"sub", "name", "iss", "aud"},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
	}
	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Initialize JwtAuth with mock configurations
			jwtAuth, err := jwt.NewJwtAuth(fix.environment, "authenticate.claims", fix.config)
			require.NoError(t, err)
			// Mock GRPC context with metadata
			md := metadata.New(map[string]string{"authorization": fmt.Sprintf("Bearer %s", fix.getToken(t, ctx))})

			ctx, err = jwtAuth.AuthenticateMethod(metadata.NewIncomingContext(ctx, md), fix.method)
			if fix.expectError {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			claims, _ := ctx.Value("authenticate.claims").(jwt2.MapClaims)
			if fix.expectClaims != nil {
				fix.expectClaims(t, claims)
			}
		})
	}
}
