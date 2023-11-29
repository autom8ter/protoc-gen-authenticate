package module

import (
	"bytes"
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
		configMap[s.Name().UpperCamelCase().String()] = configs
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

//func NewJwtAuth(ctxClaimsKey any, config map[string][]*authenticate.Config) (*JwtAuth, error)
/*

// JwtProvider is a provider that uses a JWT to authenticate a request.
message JwtProvider {
  // The expected JWT issuer.
  string issuer = 1;
  // The expected JWT audience.
  string audience = 2;
  // The expected JWT algorithm.
  Algorithm algorithm = 3;
  // The jwks uri to fetch the public key from.
  string jwks_uri = 4;
  // The environment variable that contains the secret key to verify the JWT.
  string secret_env = 5;
  // require_claims, if set, checks that the JWT contains the specified claims.
  repeated string require_claims = 6;
}

// Provider is a provider that can be used to authenticate a request.
message Provider {
  oneof provider {
    // JwtProvider is a provider that uses a JWT to authenticate a request.
    JwtProvider jwt = 1;
  }
}

*/
var tmpl = `
package {{ .Package }}

import (
	"github.com/autom8ter/proto/gen/authenticate"

	"github.com/autom8ter/protoc-gen-authenticate/jwt"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
)

type ctxKey string

const (
	// CtxClaimsKey is the context key for storing the claims
	CtxClaimsKey ctxKey = "authenticate.claims"
)

// NewAuthentication returns a new authentication interceptor
func NewAuthentication() (grpc_auth.AuthFunc, error) {
	auth, err := jwt.NewJwtAuth(CtxClaimsKey, map[string][]*authenticate.Config{
	{{- range $service, $configs := .Configs }}
	  "{{ $service }}": {
		{{- range $config := $configs }}
		{
			RequireEnv: "{{ $config.RequireEnv }}",
			Providers: []*authenticate.Provider{
				{{- range $provider := $config.Providers }}
				{
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
`
