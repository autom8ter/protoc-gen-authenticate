package module

import (
	"bytes"
	`fmt`
	"text/template"

	"github.com/autom8ter/proto/gen/authenticate"
	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"
)

// Module is the protoc-gen-authenticater module
// implements the protoc-gen-star module interface
type module struct {
	*pgs.ModuleBase
	pgsgo.Context
}

func New() pgs.Module {
	return &module{ModuleBase: &pgs.ModuleBase{}}
}

func (m *module) Name() string {
	return "authorize"
}

func (m *module) InitContext(c pgs.BuildContext) {
	m.ModuleBase.InitContext(c)
	m.Context = pgsgo.InitContext(c.Parameters())
}

func (m *module) Execute(targets map[string]pgs.File, packages map[string]pgs.Package) []pgs.Artifact {
	for _, f := range targets {
		if f.BuildTarget() {
			m.generate(f)
		}
	}
	return m.Artifacts()
}

func (m *module) generate(f pgs.File) {
	var configMap = map[string][]*authenticate.Config{}
	for _, s := range f.Services() {
		var configs []*authenticate.Config
		ok, err := s.Extension(authenticate.E_Config, &configs)
		if err != nil {
			m.AddError(err.Error())
			continue
		}
		if !ok {
			continue
		}
		for _, config := range configs {
			for _, provider := range config.Providers {
				if provider.GetName() == "" {
					m.AddError("authenticate: provider name cannot be empty")
					continue
				}
				if pjwt := provider.GetJwt(); pjwt != nil {
					if pjwt.JwksUri == "" && pjwt.SecretEnv == "" {
						m.AddError("authenticate: jwks_uri OR secret_env must be set")
						continue
					}
				}
			}
		}
		configMap[fmt.Sprintf("%s.%s", m.Context.PackageName(f).String(), s.Name())] = configs
	}
	if len(configMap) == 0 {
		return
	}
	name := f.InputPath().SetExt(".pb.authentication.go").String()

	t, err := template.New("authenticate").Parse(tmpl)
	if err != nil {
		m.AddError(err.Error())
		return
	}

	buffer := &bytes.Buffer{}
	if err := t.Execute(buffer, templateData{
		Package: m.Context.PackageName(f).String(),
		Configs: configMap,
	}); err != nil {
		m.AddError(err.Error())
		return
	}
	m.AddGeneratorFile(name, buffer.String())
}

type templateData struct {
	Package string
	Configs map[string][]*authenticate.Config
}

var tmpl = `
package {{ .Package }}

import (
	"context"

	"github.com/autom8ter/proto/gen/authenticate"

	"github.com/golang-jwt/jwt/v5"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"

	jwtAuth "github.com/autom8ter/protoc-gen-authenticate/jwt"
)

type ctxKey string

const (
	// CtxClaimsKey is the context key for storing the claims
	CtxClaimsKey ctxKey = "authenticate.claims"
)

// NewAuthentication returns a new authentication interceptor
func NewAuthentication(environment string) (grpc_auth.AuthFunc, error) {
	auth, err := jwtAuth.NewJwtAuth(environment, CtxClaimsKey, map[string][]*authenticate.Config{
	{{- range $service, $configs := .Configs }}
	  "{{ $service }}": {
		{{- range $config := $configs }}
		{
			Environment: "{{ $config.Environment }}",
			WhitelistMethods: []string{
						{{- range $method := $config.WhitelistMethods }}
						"{{ $method }}",
						{{- end }}
					},
			Providers: []*authenticate.Provider{
				{{- range $provider := $config.Providers }}
				{
					Name: "{{ $provider.Name }}",
					{{- if $provider.GetJwt }}
					Provider: &authenticate.Provider_Jwt{
						Jwt: &authenticate.JwtProvider{
							Issuer: "{{ $provider.GetJwt.Issuer }}",
							Audience: "{{ $provider.GetJwt.Audience }}",
							Algorithm: authenticate.Algorithm_{{ $provider.GetJwt.Algorithm }},
							JwksUri: "{{ $provider.GetJwt.JwksUri }}",
							SecretEnv: "{{ $provider.GetJwt.SecretEnv }}",
							RequireClaims: []string{
								{{- range $claim := $provider.GetJwt.RequireClaims }}
								"{{ $claim }}",
								{{- end }}
							},
						},
					},
					{{- end }}
				},
				{{- end }}
			},
		},
		{{- end }}
	  },
	{{- end }}
	})
	if err != nil {
		return nil, err
	}
	return auth.Verify, nil
}

func GetClaims(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(CtxClaimsKey).(jwt.MapClaims)
	if !ok {
		return nil, false
	}
	return claims, true
}
`
