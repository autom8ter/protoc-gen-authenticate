package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/autom8ter/proto/gen/authenticate"
	"github.com/golang-jwt/jwt/v5"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fetchJWKS fetches a JWKS from a given URL
func fetchJWKS(jwksURL string) (*jwt.VerificationKeySet, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %v for uri:%s", err, jwksURL)
	}
	defer resp.Body.Close()

	var keys jwt.VerificationKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode jwks: %v for uri:%s", err, jwksURL)
	}
	return &keys, nil
}

// JwtAuth authenticates inbound JWTs
type JwtAuth struct {
	environment string
	config      map[string][]*authenticate.Config
	cachedKeys  sync.Map
	ctxKey      any
}

// NewJwtAuth returns a new JwtAuth instance
func NewJwtAuth(environment string, ctxClaimsKey any, config map[string][]*authenticate.Config) (*JwtAuth, error) {
	j := &JwtAuth{
		config:      config,
		cachedKeys:  sync.Map{},
		ctxKey:      ctxClaimsKey,
		environment: environment,
	}
	for _, configs := range config {
		for _, serviceConfig := range configs {
			if serviceConfig.Environment != "" && environment != serviceConfig.Environment {
				continue
			}
			for _, provider := range serviceConfig.Providers {
				if provider.GetJwt() == nil {
					continue
				}
				providerJWT := provider.GetJwt()
				if providerJWT.JwksUri != "" {
					keys, err := fetchJWKS(providerJWT.JwksUri)
					if err != nil {
						return nil, err
					}
					j.cachedKeys.Store(providerJWT.JwksUri, keys)
				}
			}
		}
	}
	go func() {
		ticker := time.NewTicker(time.Minute * 5)
		for {
			select {
			case <-ticker.C:
				j.cachedKeys.Range(func(key, value any) bool {
					keys, err := fetchJWKS(key.(string))
					if err != nil {
						panic(err)
					}
					j.cachedKeys.Store(key, keys)
					return true
				})
			}
		}
	}()
	return j, nil
}

// AuthenticateMethod verifies the JWT for a given method
func (j *JwtAuth) AuthenticateMethod(ctx context.Context, fullMethodName string) (context.Context, error) {

	methodSplit := strings.Split(fullMethodName, "/")
	if len(methodSplit) != 3 {
		return nil, status.Errorf(codes.Internal, "authenticate: invalid method name")
	}
	methodName := strings.Split(fullMethodName, "/")[2]
	svcName := strings.Split(fullMethodName, "/")[1]
	var errors []string
	for svc, configs := range j.config {
		if svc != svcName {
			continue
		}
		for _, serviceConfig := range configs {
			if serviceConfig.Environment != "" && j.environment != serviceConfig.Environment {
				continue
			}
			if len(serviceConfig.WhitelistMethods) > 0 {
				if lo.Contains(serviceConfig.WhitelistMethods, methodName) {
					return ctx, nil
				}
			}

			for _, p := range serviceConfig.Providers {
				if p.GetJwt() == nil {
					continue
				}
				jwtToken, err := grpc_auth.AuthFromMD(ctx, "bearer")
				if err != nil {
					return nil, status.Errorf(codes.Unauthenticated, err.Error())
				}
				providerJWT := p.GetJwt()
				claims, err := j.verifyJWT(ctx, jwtToken, p.Name, providerJWT)
				if err != nil {
					errors = append(errors, err.Error())
					continue
				}
				return context.WithValue(ctx, j.ctxKey, claims), nil
			}
		}
	}
	if len(errors) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authenticate: missing jwt provider for method: %v", methodName)
	}
	return nil, status.Errorf(codes.Unauthenticated, strings.Join(errors, "\n"))
}

// Authenticate verifies the JWT
func (j *JwtAuth) Authenticate(ctx context.Context) (context.Context, error) {
	method, ok := grpc.Method(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "authenticate: missing grpc method")
	}
	return j.AuthenticateMethod(ctx, method)
}

func (j *JwtAuth) verifyJWT(ctx context.Context, jwtToken, name string, provider *authenticate.JwtProvider) (jwt.MapClaims, error) {
	if provider.SecretEnv == "" && provider.JwksUri == "" {
		return nil, fmt.Errorf("authenticate: missing secret env / jwks uri - at least one is required")
	}
	if provider.Algorithm == authenticate.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, fmt.Errorf("authenticate(%s): missing jwt signing algorithm", name)
	}
	// Parse the token
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		switch provider.Algorithm {
		case authenticate.Algorithm_HS256:
			if token.Header["alg"] != "HS256" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_HS384:
			if token.Header["alg"] != "HS384" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_HS512:
			if token.Header["alg"] != "HS512" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		//case authenticate.Algorithm_PS256, authenticate.Algorithm_PS384, authenticate.Algorithm_PS512:
		case authenticate.Algorithm_RS256:
			if token.Header["alg"] != "RS256" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_RS384:
			if token.Header["alg"] != "RS384" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_RS512:
			if token.Header["alg"] != "RS512" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_ES256:
			if token.Header["alg"] != "ES256" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_ES384:
			if token.Header["alg"] != "ES384" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		case authenticate.Algorithm_ES512:
			if token.Header["alg"] != "ES512" {
				return nil, fmt.Errorf("authenticate(%s): Unexpected signing method: %v", name, token.Header["alg"])
			}
		default:
			return nil, fmt.Errorf("authenticate(%s): invalid jwt signing algorithm: %v", provider.Algorithm.String(), name)
		}
		if provider.SecretEnv != "" && os.Getenv(provider.SecretEnv) != "" {
			return []byte(os.Getenv(provider.SecretEnv)), nil
		}
		if provider.JwksUri != "" {
			keys, ok := j.cachedKeys.Load(provider.JwksUri)
			if !ok {
				return nil, status.Errorf(codes.Internal, "authenticate(%s): missing jwks for uri: %v", provider.JwksUri, name)
			}
			return keys.(*jwt.VerificationKeySet), nil
		}
		return nil, status.Errorf(codes.Internal, "authenticate(%s): missing secret env or jwks uri", name)
	})
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}
	if !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "authenticate(%s): invalid token", name)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		for _, required := range provider.RequireClaims {
			if _, ok := claims[required]; !ok {
				return nil, status.Errorf(codes.Unauthenticated, "authenticate(%s): missing required claim: %v", required, name)
			}
		}
		if provider.Audience != "" && claims["aud"] != provider.Audience {
			return nil, status.Errorf(codes.Unauthenticated, "authenticate(%s): invalid audience", name)
		}
		if provider.Issuer != "" && claims["iss"] != provider.Issuer {
			return nil, status.Errorf(codes.Unauthenticated, "authenticate(%s): invalid issuer", name)
		}
		return claims, nil
	}
	return nil, status.Errorf(codes.Unauthenticated, "authenticate(%s): invalid claims", name)
}

// Sign signs a JWT
func Sign(ctx context.Context, claims jwt.MapClaims, secret string, algorithm jwt.SigningMethod) (string, error) {
	token := jwt.NewWithClaims(algorithm, claims)
	return token.SignedString([]byte(secret))
}
