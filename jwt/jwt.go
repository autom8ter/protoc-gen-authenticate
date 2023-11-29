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
	config     map[string][]*authenticate.Config
	cachedKeys map[string]*jwt.VerificationKeySet
	mu         sync.RWMutex
	ctxKey     any
}

func NewJwtAuth(ctxClaimsKey any, config map[string][]*authenticate.Config) (*JwtAuth, error) {
	j := &JwtAuth{
		config:     config,
		cachedKeys: make(map[string]*jwt.VerificationKeySet),
		mu:         sync.RWMutex{},
		ctxKey:     ctxClaimsKey,
	}
	for _, configs := range config {
		for _, serviceConfig := range configs {
			if serviceConfig.RequireEnv != "" && os.Getenv("GRPC_AUTH") != serviceConfig.RequireEnv {
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
					j.cachedKeys[providerJWT.JwksUri] = keys
				}
			}
		}
	}
	go func() {
		ticker := time.NewTicker(time.Minute * 5)
		for {
			select {
			case <-ticker.C:
				j.mu.RLock()
				keys := j.cachedKeys
				j.mu.RUnlock()
				for uri, _ := range keys {
					keys, err := fetchJWKS(uri)
					if err != nil {
						fmt.Println(err.Error())
						continue
					}
					j.mu.Lock()
					j.cachedKeys[uri] = keys
					j.mu.Unlock()
				}
			}
		}
	}()
	return j, nil
}

func (j *JwtAuth) Verify(ctx context.Context) (context.Context, error) {
	jwtToken, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}
	// "/service/method".
	method, ok := grpc.Method(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing method")
	}
	methodName := strings.Split(method, "/")[2]
	svcName := strings.Split(method, "/")[1]
	var errors []string
	for svc, configs := range j.config {
		if svc != svcName {
			continue
		}
		for _, serviceConfig := range configs {

			if serviceConfig.RequireEnv != "" && os.Getenv("GRPC_AUTH") != serviceConfig.RequireEnv {
				continue
			}
			if lo.Contains(serviceConfig.WhitelistMethods, methodName) {
				return ctx, nil
			}
			for _, p := range serviceConfig.Providers {
				if p.GetJwt() == nil {
					continue
				}
				providerJWT := p.GetJwt()
				claims, err := j.verifyJWT(ctx, jwtToken, providerJWT)
				if err != nil {
					errors = append(errors, err.Error())
					continue
				}
				return context.WithValue(ctx, j.ctxKey, claims), nil
			}
		}
	}
	return nil, status.Errorf(codes.Unauthenticated, strings.Join(errors, "\n"))
}

func (j *JwtAuth) verifyJWT(ctx context.Context, jwtToken string, provider *authenticate.JwtProvider) (jwt.MapClaims, error) {
	if provider.SecretEnv == "" && provider.JwksUri == "" {
		return nil, fmt.Errorf("authenticate: missing secret env / jwks uri - at least one is required")
	}
	if provider.Algorithm == authenticate.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, fmt.Errorf("authenticate: missing jwt signing algorithm")
	}
	// Parse the token
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		switch provider.Algorithm {
		case authenticate.Algorithm_HS256, authenticate.Algorithm_HS384, authenticate.Algorithm_HS512:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("authenticate: Unexpected signing method: %v", token.Header["alg"])
			}
		case authenticate.Algorithm_RS256, authenticate.Algorithm_RS384, authenticate.Algorithm_RS512:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("authenticate: Unexpected signing method: %v", token.Header["alg"])
			}
		case authenticate.Algorithm_ES256, authenticate.Algorithm_ES384, authenticate.Algorithm_ES512:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("authenticate: Unexpected signing method: %v", token.Header["alg"])
			}
		default:
			return nil, fmt.Errorf("authenticate: invalid jwt signing algorithm: %v", provider.Algorithm)
		}
		if provider.SecretEnv != "" && os.Getenv(provider.SecretEnv) != "" {
			return []byte(os.Getenv(provider.SecretEnv)), nil
		}
		if provider.JwksUri != "" {
			j.mu.RLock()
			keys, ok := j.cachedKeys[provider.JwksUri]
			j.mu.RUnlock()
			if !ok {
				return nil, status.Errorf(codes.Internal, "missing jwks for uri: %v", provider.JwksUri)
			}
			return keys, nil
		}
		return nil, status.Errorf(codes.Internal, "authenticate: missing secret env or jwks uri")
	})
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		for _, required := range provider.RequireClaims {
			if _, ok := claims[required]; !ok {
				return nil, status.Errorf(codes.Unauthenticated, "authenticate: missing required claim: %v", required)
			}
		}
		if provider.Audience != "" && claims["aud"] != provider.Audience {
			return nil, status.Errorf(codes.Unauthenticated, "authenticate: invalid audience")
		}
		if provider.Issuer != "" && claims["iss"] != provider.Issuer {
			return nil, status.Errorf(codes.Unauthenticated, "authenticate: invalid issuer")
		}
		return claims, nil
	}
	return nil, status.Errorf(codes.Unauthenticated, "authenticate: invalid claims")
}
