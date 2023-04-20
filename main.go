package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/aquasecurity/yaml"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	flag "github.com/spf13/pflag"
)

const (
	// HeaderAuthorization is the name of the header to obtain the bearer token from
	HeaderAuthorization = "Authorization"
	// HeaderAuthorizationBearerPrefix is the prefix to the Authorization header if it contains a bearer token
	HeaderAuthorizationBearerPrefix = "Bearer "
	// DefaultPolicy is the default value for the config oidc.policy field.
	// It assumes the user is using keycloak in a default configuration and checks if the requested tenant ID appears in the users realm roles
	DefaultPolicy = `
{{- if not (has .Tenant.ID .Token.Claims.realm_access.roles) }}
Forbidden: You are not part of this tenant
{{- end }}
`
	// DefaultAddress is the default value of the config http.address field.
	// It listens on localhost only on port 8088.
	DefaultAddress = "127.0.0.1:8088"
	// DefaultTenantsPath is the default value of the config http.tenantsPath field.
	// It assuems tenant servers have --static-prefix=tenants/${tenant_id}
	DefaultTenantsPath = "/tenants/"
	// DefaultAccessTokenHeader is the default value of the config oidc.accessTokenHeader.
	// It assumes the server is being proxied by the OAuth2Proxy (https://github.com/oauth2-proxy/oauth2-proxy/) with --pass-access-token
	DefaultAccessTokenHeader = "X-Forwarded-Access-Token"
)

var (
	ConfigPath = flag.String("config", "./mlflow-oidc-proxy.cfg", "Path to YAML/JSON formatted configuration file")
	HomePage   *template.Template
)

func init() {
	var err error
	HomePage, err = template.New("homepage").Funcs(sprig.FuncMap()).Parse(`
{{- $dot := . }}
<head>
<title>MLFlow Tenant List</title>
</head>
<h1>MLFlow Tenant List</h1>
<body>
{{- with .tenants }}
<table>
  <tr>
    <th>Name</th>
  </tr>
  {{- range $tenant := . }}
  <tr>
	<td><a href="{{ $dot.baseURL }}/tenants/{{ $tenant.ID }}/">{{ $tenant.Name }}</a></td>
  </tr>
  {{- end }}
</table>
{{- else }}
You do not have access to any tenants, please contact your administrator
{{- end }}
</body>
`)
	if err != nil {
		panic(err)
	}
}

type URL struct {
	Inner *url.URL
	Raw   string
}

func (u *URL) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, &u.Raw)
	if err != nil {
		return err
	}
	u.Inner, err = url.Parse(u.Raw)
	return err
}

type Address struct {
	URL
}

func (a *Address) UnmarshalJSON(bytes []byte) error {
	s := string(bytes)
	err := a.URL.UnmarshalJSON([]byte(s[:1] + "tcp://" + s[1:]))
	if err != nil {
		return err
	}
	a.URL.Inner.Scheme = ""
	return nil
}

func (a *Address) String() string {
	return strings.TrimPrefix(a.URL.Inner.String(), "//")
}

type Duration struct {
	Inner time.Duration
}

func (d *Duration) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	fmt.Println(s)
	d.Inner, err = time.ParseDuration(s)
	if err != nil {
		return err
	}
	return nil
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

type ProxyOIDCConfig struct {
	AccessTokenHeader string   `json:"accessTokenHeader"`
	SyncInterval      Duration `json:"syncInterval"`
	WellKnownURL      URL      `json:"wellKnownURL"`
	Policy            Template `json:"policy"`
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
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type ProxyConfig struct {
	OIDC   ProxyOIDCConfig   `json:"oidc"`
	MLFlow ProxyMLFlowConfig `json:"mlflow"`
	HTTP   ProxyHTTPConfig   `json:"http"`
	TLS    ProxyTLSConfig    `json:"tls"`
}

func (p *ProxyConfig) ApplyDefaults() (err error) {
	if p.OIDC.AccessTokenHeader == "" {
		p.OIDC.AccessTokenHeader = DefaultAccessTokenHeader
	}

	if p.OIDC.Policy.Raw == "" {
		_, err = p.OIDC.Policy.Inner.Parse(DefaultPolicy)
		if err != nil {
			return err
		}
	}

	if p.HTTP.Address.Raw == "" {
		p.HTTP.Address.Inner, err = url.Parse(DefaultAddress)
		if err != nil {
			return err
		}
	}

	if p.HTTP.ExternalURL.Raw == "" {
		p.HTTP.ExternalURL.Inner, err = url.Parse(fmt.Sprintf("http://%s", p.HTTP.Address.Inner.String()))
		if err != nil {
			return err
		}
	}

	if p.HTTP.TenantsPath == "" {
		p.HTTP.TenantsPath = DefaultTenantsPath
	}

	return nil
}

type ProxyTenantState struct {
	*ProxyMLFlowTenant
	httputil.ReverseProxy
}

type ProxyState struct {
	Config  *ProxyConfig
	Tenants map[string]*ProxyTenantState
	BaseURL *url.URL
	*http.ServeMux
}

func JoinPaths(p1, p2 string) string {
	return strings.TrimSuffix(p1, "/") + "/" + strings.TrimPrefix(p2, "/")
}

func WithTrailingSlash(p string) string {
	return JoinPaths(p, "")
}

func NewProxy(config ProxyConfig) (*ProxyState, error) {
	state := &ProxyState{
		Config:  &config,
		Tenants: make(map[string]*ProxyTenantState, len(config.MLFlow.Tenants)),
		BaseURL: config.HTTP.ExternalURL.Inner,
	}

	for ix, tenant := range config.MLFlow.Tenants {
		state.Tenants[tenant.ID] = &ProxyTenantState{}
		state.Tenants[tenant.ID].ProxyMLFlowTenant = &config.MLFlow.Tenants[ix]
		state.Tenants[tenant.ID].ReverseProxy = httputil.ReverseProxy{
			Director:       state.Tenants[tenant.ID].director,
			ModifyResponse: state.Tenants[tenant.ID].modifyResponse,
			ErrorLog:       log.Default(),
		}
	}
	state.ServeMux = http.NewServeMux()
	state.ServeMux.HandleFunc(JoinPaths(state.BaseURL.Path, ""), state.Home)
	state.ServeMux.HandleFunc(WithTrailingSlash(JoinPaths(state.BaseURL.Path, config.HTTP.TenantsPath)), state.Proxy)
	// We want the healthcheck endpoint to be acessible both externally and internally
	state.ServeMux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("OK"))
	})
	if state.BaseURL.Path != "" {
		state.ServeMux.HandleFunc(JoinPaths(state.BaseURL.Path, "/health"), func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("OK"))
		})
	}
	return state, nil
}

type PolicyContext struct {
	Tenant  *ProxyMLFlowTenant
	Token   *jwt.Token
	Request *http.Request
}

func (p *ProxyState) ValidateRequest(token *jwt.Token, w http.ResponseWriter, req *http.Request) (*ProxyTenantState, error) {
	parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/"), "/", 3)
	log.Printf("Got request for %s (%v) for user %#v\n", req.URL.String(), parts, token)
	if len(parts) < 3 {
		http.Redirect(w, req, p.BaseURL.String(), http.StatusFound)
		return nil, nil
	}
	tenantID := parts[1]
	tenant, ok := p.Tenants[tenantID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(fmt.Sprintf("No such tenant: %s", tenantID)))
		return nil, nil
	}
	errBuilder := strings.Builder{}

	err := p.Config.OIDC.Policy.Inner.Execute(
		&errBuilder,
		PolicyContext{
			Token:   token,
			Request: req,
			Tenant:  tenant.ProxyMLFlowTenant,
		},
	)

	if err != nil {
		return nil, err
	}

	errMsg := errBuilder.String()

	if len(strings.TrimSpace(errMsg)) != 0 {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(errMsg))
		return nil, nil
	}

	if strings.HasPrefix(parts[2], "api/") {
		req.URL.Path = parts[2]
	}

	return tenant, nil
}

func (p *ProxyState) GetBearerToken(r *http.Request) (string, bool) {
	authHeader, ok := r.Header[HeaderAuthorization]
	if !ok {
		return "", false
	}
	if len(authHeader) == 0 {
		return "", false
	}
	if len(authHeader[0]) == 0 {
		return "", false
	}
	if !strings.HasPrefix(authHeader[0], HeaderAuthorizationBearerPrefix) {
		return "", false
	}
	return strings.TrimPrefix(authHeader[0], HeaderAuthorizationBearerPrefix), true
}

func (p *ProxyState) GetAccessToken(r *http.Request) (string, bool) {
	token, ok := r.Header[p.Config.OIDC.AccessTokenHeader]
	if !ok {
		return "", false
	}
	if len(token) == 0 {
		return "", false
	}
	if len(token[0]) == 0 {
		return "", false
	}
	return token[0], true
}

func (p *ProxyState) ExtractClaims(r *http.Request) (token *jwt.Token, err error) {
	_ /*bearerToken*/, hasBearerToken := p.GetBearerToken(r)
	accessToken, hasAccessToken := p.GetAccessToken(r)
	if !hasBearerToken && !hasAccessToken {
		return nil, fmt.Errorf("No access or bearer token present")
	}
	/*
		if hasBearerToken && hasAccessToken {
			return nil, fmt.Errorf("Both access and bearer token provided")
		}
		tokenString := bearerToken
		if hasAccessToken {
			log.Printf("Using access token for claims\n")
			tokenString = accessToken
		} else {
			log.Printf("Using bearer token for claims\n")
		}
	*/
	tokenString := accessToken
	//token, err := jwt.NewParser().Parse(rawToken[0], func(token *jwt.Token) (interface{}, error) { return token, nil })
	claims := make(jwt.MapClaims)
	// TODO: Deal with signature
	token, _, err = jwt.NewParser().ParseUnverified(tokenString, claims)
	return
}

func MergeURLs(dest, src *url.URL) {
	dest.Scheme = src.Scheme
	dest.Opaque = src.Opaque
	dest.User = src.User
	dest.Host = src.Host
	dest.Path = src.Path + dest.Path
	dest.RawPath += src.RawPath
	dest.ForceQuery = src.ForceQuery
	destQuery, err := url.ParseQuery(dest.RawQuery)
	if err != nil {
		log.Printf("Error parsing query, using empty query: %s\n", err)
	}
	srcQuery, err := url.ParseQuery(src.RawQuery)
	if err != nil {
		log.Printf("Error parsing query, using empty query: %s\n", err)
	}
	for k, v := range srcQuery {
		destQuery[k] = v
	}
	dest.RawQuery = destQuery.Encode()
	dest.Fragment = src.Fragment
	dest.RawFragment = src.RawFragment
}

func (t *ProxyMLFlowTenant) director(r *http.Request) {
	MergeURLs(r.URL, t.Upstream.Inner)
}

func (tenant *ProxyMLFlowTenant) modifyResponse(resp *http.Response) error {
	log.Println(resp)
	return nil
}

func (p *ProxyState) Home(w http.ResponseWriter, req *http.Request) {
	requestUUID, err := uuid.NewRandom()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	requestID := requestUUID.String()

	token, err := p.ExtractClaims(req)
	if err != nil {
		log.Printf("Got invalid token (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid token. Request ID %s", requestID)))
		return
	}

	tenants := make([]*ProxyMLFlowTenant, 0, len(p.Tenants))
	for _, tenant := range p.Tenants {
		errBuilder := strings.Builder{}

		err = p.Config.OIDC.Policy.Inner.Execute(
			&errBuilder,
			PolicyContext{
				Token:   token,
				Request: req,
				Tenant:  tenant.ProxyMLFlowTenant,
			},
		)

		if err != nil {
			log.Printf("Got invalid token (Request ID: %s): %v\n", requestID, err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid token. Request ID %s", requestID)))
			return
		}

		errMsg := errBuilder.String()

		if len(strings.TrimSpace(errMsg)) != 0 {
			continue
		}

		tenants = append(tenants, tenant.ProxyMLFlowTenant)
	}
	err = HomePage.Execute(w, map[string]interface{}{
		"tenants": tenants,
		"baseURL": p.BaseURL,
	})

	if err != nil {
		log.Printf("Error rendering homepage: %v\n", err)
	}
}

func (p *ProxyState) Proxy(w http.ResponseWriter, r *http.Request) {
	requestUUID, err := uuid.NewRandom()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	requestID := requestUUID.String()
	token, err := p.ExtractClaims(r)
	if err != nil {
		log.Printf("Got invalid token (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Invalid token. Request ID %s", requestID)))
		return
	}

	tenant, err := p.ValidateRequest(token, w, r)
	if err != nil {
		log.Printf("Error during policy execution (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("Internal Error. Request ID %s\n", requestID)))
		return
	}
	log.Printf("%s: Rewrote URL to %s\n", requestID, r.URL.String())

	if tenant != nil {
		tenant.ServeHTTP(w, r)
	}
}

func (p *ProxyState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.ServeMux.ServeHTTP(w, r)
}

func (p *ProxyState) ListenAndServe() error {
	server := http.Server{
		Addr:    p.Config.HTTP.Address.String(),
		Handler: p,
	}
	if p.Config.TLS.Enabled {
		fmt.Printf("Listening on %s (TLS)\n", p.Config.HTTP.Address.Inner.String())
		return server.ListenAndServeTLS(p.Config.TLS.CertFile, p.Config.TLS.KeyFile)
	}
	fmt.Printf("Listening on %s (Plaintext)\n", p.Config.HTTP.Address.Inner.String())
	return server.ListenAndServe()
}

// TODO: Add an optional endpoint which, if called with a valid token, will set the password based on a template given the token and the query claims
// This will allow users to set their internal nexus password, which should not be needed when accessing through the proxy, but if accessed through a second endpoint which bypasses the proxy, will act as a "token", rather than an SSO password, for example, in a maven settings.xml

func main() {
	flag.Parse()

	configFile, err := os.Open(*ConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	configBytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := ProxyConfig{}

	config.OIDC.Policy.Inner = template.New("oidc.policy").Funcs(sprig.FuncMap())

	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal(err)
	}

	err = config.ApplyDefaults()
	if err != nil {
		log.Fatal(err)
	}

	proxy, err := NewProxy(config)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(proxy.ListenAndServe())
}
