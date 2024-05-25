package proxy

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"strings"

	"github.com/Masterminds/sprig"
	"github.com/meln5674/gotoken"
	"github.com/pkg/errors"
)

const (
	// DefaultPolicy is the default value for the config oidc.policy field.
	// It assumes the user is using keycloak in a default configuration and checks if the requested tenant ID appears in the users realm roles
	DefaultPolicy = `
{{- if not (has .Tenant.ID .Token.Claims.realm_access.roles) }}
Forbidden: You are not part of this tenant
{{- end }}
`
	DefaultGetSubject = `{{ .Token.Claims.preferred_username }}`

	// DefaultAddress is the default value of the config http.address field.
	// It listens on localhost only on port 8088.
	DefaultAddress = "127.0.0.1:8088"
	// DefaultTenantsPath is the default value of the config http.tenantsPath field.
	// It assuems tenant servers have --static-prefix=tenants/${tenant_id}
	DefaultTenantsPath = "/tenants/"
	// DefaultAccessTokenHeader is the default value of the config oidc.tokenHeader.
	// It assumes the server is being proxied by the OAuth2Proxy (https://github.com/oauth2-proxy/oauth2-proxy/) with --pass-access-token
	DefaultTokenHeader = "X-Forwarded-Access-Token"
	// DefaulTokenMode is the default value of the config oidc.tokenMode.
	DefaultTokenMode = gotoken.TokenModeRaw
	// DefaultCerificate header is the default value of the config robots.certificateHeader
	DefaultCertificateHeader = "Ssl-Client-Cert"
)

var (
	ParsedDefaultPolicy     Template
	ParsedDefaultGetSubject Template
	ParsedDefaultAddress    Address
)

func initDefaults() {
	var err error
	ParsedDefaultPolicy.Inner, err = template.New("oidc.policy [default]").Funcs(sprig.FuncMap()).Funcs(FuncMap()).Parse(DefaultPolicy)
	if err != nil {
		panic(err)
	}
	ParsedDefaultPolicy.Raw = DefaultPolicy

	ParsedDefaultGetSubject.Inner, err = template.New("oidc.getSubject [default]").Funcs(sprig.FuncMap()).Funcs(FuncMap()).Parse(DefaultGetSubject)
	if err != nil {
		panic(err)
	}
	ParsedDefaultGetSubject.Raw = DefaultGetSubject

	_, err = ParsedDefaultAddress.Parse(DefaultAddress)
	if err != nil {
		panic(err)
	}
}

type URL struct {
	Inner *url.URL
	Raw   string
}

func (u *URL) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	_, err = u.Parse(s)
	return err
}

func (u *URL) Parse(s string) (*URL, error) {
	res, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	u.Inner = res
	u.Raw = s
	return u, nil
}

type Address struct {
	URL
}

func (a *Address) Parse(s string) (*Address, error) {
	_, err := a.URL.Parse("tcp://" + s)
	if err != nil {
		return nil, err
	}
	a.URL.Inner.Scheme = ""
	a.URL.Raw = s
	return a, nil
}

func (a *Address) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	_, err = a.Parse(s)
	return err
}

func (a *Address) String() string {
	return strings.TrimPrefix(a.URL.Inner.String(), "//")
}

type Template struct {
	Inner *template.Template
	Raw   string
}

func (t *Template) UnmarshalJSON(bytes []byte) error {
	if t.Inner == nil {
		panic("Inner template was not initialized")
	}

	err := json.Unmarshal(bytes, &t.Raw)
	if err != nil {
		return err
	}
	_, err = t.Inner.Parse(t.Raw)
	return err
}

type CertificateFromPath struct {
	Raw   string
	PEM   string
	Inner *x509.Certificate
}

func (c *CertificateFromPath) UnmarshalJSON(bytes []byte) error {
	var path string
	err := json.Unmarshal(bytes, &path)
	if err != nil {
		return err
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	der, rest := pem.Decode(pemBytes)
	if der == nil {
		return fmt.Errorf("No PEM data found in file %s", path)
	}
	if len(rest) != 0 {
		return fmt.Errorf("Trailing data after PEM certificate in file %s", path)
	}
	cert, err := x509.ParseCertificate(der.Bytes)
	if err != nil {
		return err
	}
	c.Raw = path
	c.Inner = cert
	c.PEM = string(pemBytes)
	return nil
}

type SecretTokenFromPath struct {
	Token string
}

func (c *SecretTokenFromPath) UnmarshalJSON(bytes []byte) error {
	var path string
	err := json.Unmarshal(bytes, &path)
	if err != nil {
		return err
	}
	tokenBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c.Token = string(tokenBytes)
	return nil
}

type ProxyOIDCConfig struct {
	TokenHeader    string            `json:"tokenHeader"`
	TokenMode      gotoken.TokenMode `json:"tokenMode"`
	WellKnownURL   URL               `json:"wellKnownURL"`
	Policy         Template          `json:"policy"`
	GetSubject     Template          `json:"getSubject"`
	ExtraVariables interface{}       `json:"extraVariables"`
}

type ProxyMLFlowTenant struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Upstream URL    `json:"upstream"`
}
type ProxyMLFlowConfig struct {
	Tenants []ProxyMLFlowTenant `json:"tenants"`
}

type ProxyHTTPConfig struct {
	Address     Address `json:"address"`
	ExternalURL URL     `json:"externalURL"`
	TenantsPath string  `json:"tenantsPath"`
}

type ProxyTLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	Terminated bool   `json:"terminated"`
}

type ProxyRobotConfig struct {
	CertificateHeader string  `json:"certificateHeader"`
	Robots            []Robot `json:"robots"`
}

type ProxyConfig struct {
	OIDC   ProxyOIDCConfig   `json:"oidc"`
	MLFlow ProxyMLFlowConfig `json:"mlflow"`
	HTTP   ProxyHTTPConfig   `json:"http"`
	TLS    ProxyTLSConfig    `json:"tls"`
	Robots ProxyRobotConfig  `json:"robots"`
}

func (p *ProxyConfig) Init() *ProxyConfig {
	p.OIDC.GetSubject.Inner = template.New("oidc.getSubject").Funcs(sprig.FuncMap()).Funcs(FuncMap())
	p.OIDC.Policy.Inner = template.New("oidc.policy").Funcs(sprig.FuncMap()).Funcs(FuncMap())
	return p
}

func (p *ProxyConfig) ApplyDefaults() (err error) {
	if p.OIDC.TokenHeader == "" {
		p.OIDC.TokenHeader = DefaultTokenHeader
	}

	if p.OIDC.TokenMode == "" {
		p.OIDC.TokenMode = DefaultTokenMode
	}

	if p.OIDC.Policy.Raw == "" {
		p.OIDC.Policy = ParsedDefaultPolicy
	}

	if p.OIDC.GetSubject.Raw == "" {
		p.OIDC.GetSubject = ParsedDefaultGetSubject
	}

	if p.HTTP.Address.Raw == "" {
		p.HTTP.Address = ParsedDefaultAddress
	}

	if p.HTTP.ExternalURL.Raw == "" {
		externalURL := fmt.Sprintf("http://%s", p.HTTP.Address.String())
		_, err := p.HTTP.ExternalURL.Parse(externalURL)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to http.externalURL from http.address as %s", externalURL))
		}
	}

	if p.HTTP.TenantsPath == "" {
		p.HTTP.TenantsPath = DefaultTenantsPath
	}

	if p.Robots.CertificateHeader == "" {
		p.Robots.CertificateHeader = DefaultCertificateHeader
	}

	return nil
}
