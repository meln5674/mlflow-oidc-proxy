package proxy

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"strings"

	"github.com/Masterminds/sprig"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
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
	HomePage             *template.Template
	ParsedDefaultPolicy  Template
	ParsedDefaultAddress Address
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
  <thead>
  <tr>
    <th>Name</th>
  </tr>
  </thead>
  <tbody>
  {{- range $tenant := . }}
  <tr id="{{ $tenant.ID }}">
	<td><a href="{{ $dot.baseURL }}/tenants/{{ $tenant.ID }}/">{{ $tenant.Name }}</a></td>
  </tr>
  {{- end }}
  <tbody>
</table>
{{- else }}
You do not have access to any tenants, please contact your administrator
{{- end }}
</body>
`)
	if err != nil {
		panic(err)
	}

	ParsedDefaultPolicy.Inner, err = template.New("oidc.policy [default]").Funcs(sprig.FuncMap()).Parse(DefaultPolicy)
	if err != nil {
		panic(err)
	}
	ParsedDefaultPolicy.Raw = DefaultPolicy

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

type ProxyOIDCConfig struct {
	AccessTokenHeader string   `json:"accessTokenHeader"`
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

func (p *ProxyConfig) Init() *ProxyConfig {
	p.OIDC.Policy.Inner = template.New("oidc.policy").Funcs(sprig.FuncMap())
	return p
}

func (p *ProxyConfig) ApplyDefaults() (err error) {
	if p.OIDC.AccessTokenHeader == "" {
		p.OIDC.AccessTokenHeader = DefaultAccessTokenHeader
	}

	if p.OIDC.Policy.Raw == "" {
		p.OIDC.Policy = ParsedDefaultPolicy
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

	return nil
}

type ProxyTenantState struct {
	*ProxyMLFlowTenant
	Proxy *ProxyState
	httputil.ReverseProxy
}

func (t *ProxyTenantState) director(r *http.Request) {
	t.Proxy.MergeURLs(r.URL, t.Upstream.Inner)
	t.Proxy.Log.Printf("Making request to %s (%#v)\n", r.URL.String(), r.URL)
}

func (t *ProxyTenantState) modifyResponse(resp *http.Response) error {
	t.Proxy.Log.Printf("%#v\n", resp)
	return nil
}

func (t *ProxyTenantState) buildReverseProxy(logger *log.Logger) {
	t.ReverseProxy = httputil.ReverseProxy{
		ModifyResponse: t.modifyResponse,
		Director:       t.director,
		ErrorLog:       logger,
	}
}

type ProxyState struct {
	Config  *ProxyConfig
	Tenants map[string]*ProxyTenantState
	BaseURL *url.URL
	*http.ServeMux
	Log *log.Logger

	HomeURL        string
	BasePath       string
	TenantsPath    string
	LongHealthPath string
}

func JoinPaths(p1 string, ps ...string) string {
	b := strings.Builder{}
	b.WriteString(strings.TrimPrefix(strings.TrimSuffix(p1, "/"), "/"))
	for _, p := range ps {
		b.WriteString("/")
		b.WriteString(strings.TrimPrefix(strings.TrimSuffix(p, "/"), "/"))
	}
	s := b.String()
	if s == "" {
		return "/"
	}
	return s
}

func WithTrailingSlash(p string) string {
	return WithoutTrailingSlash(p) + "/"
}

func WithoutTrailingSlash(p string) string {
	return strings.TrimSuffix(p, "/")
}

type ProxyOptions struct {
	Log *log.Logger
}

func NewProxy(config ProxyConfig, opts ProxyOptions) (*ProxyState, error) {
	state := &ProxyState{
		Config:  &config,
		Tenants: make(map[string]*ProxyTenantState, len(config.MLFlow.Tenants)),
		BaseURL: config.HTTP.ExternalURL.Inner,
	}

	logger := opts.Log
	if logger == nil {
		logger = log.Default()
	}
	state.Log = logger

	for ix, tenant := range config.MLFlow.Tenants {
		if strings.Contains(tenant.ID, "/") {
			return nil, fmt.Errorf("Invalid tenant ID: %s", tenant.ID)
		}
		tenantState := &ProxyTenantState{
			Proxy:             state,
			ProxyMLFlowTenant: &config.MLFlow.Tenants[ix],
		}
		tenantState.buildReverseProxy(logger)
		state.Tenants[tenant.ID] = tenantState
	}
	state.HomeURL = WithTrailingSlash(state.BaseURL.String())
	state.BasePath = WithoutTrailingSlash(state.BaseURL.Path)
	state.TenantsPath = WithoutTrailingSlash(JoinPaths(state.BaseURL.Path, config.HTTP.TenantsPath))
	// We want the healthcheck endpoint to be acessible both externally and internally
	state.LongHealthPath = JoinPaths(state.BaseURL.Path, "/health")
	return state, nil
}

type PolicyContext struct {
	Tenant  *ProxyMLFlowTenant
	Token   *jwt.Token
	Request *http.Request
}

func (p *ProxyState) InternalError(w http.ResponseWriter, req *http.Request, requestID string, msg string, err error) {
	p.Log.Printf("Error %s (Request ID: %s): %v\n", requestID, msg, err)
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(fmt.Sprintf("Internal error, please contact your administrator. Request ID %s", requestID)))
}

func (p *ProxyState) ValidateRequest(w http.ResponseWriter, req *http.Request, requestID string, token *jwt.Token) (*ProxyTenantState, error) {
	parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, p.BasePath+"/"), "/", 3)
	p.Log.Printf("Got request for %s (%v) for user %#v\n", req.URL.String(), parts, token)

	// This shouldn't be possible with how ServeHTTP works,
	// but this is here just in case to prevent panics
	if len(parts) < 2 {
		http.Redirect(w, req, p.HomeURL, http.StatusPermanentRedirect)
		return nil, nil
	}

	tenantID := parts[1]
	tenant, ok := p.Tenants[tenantID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(fmt.Sprintf("No such tenant: %s", tenantID)))
		return nil, nil
	}
	authMsg, err := p.Authorize(req, tenant.ProxyMLFlowTenant, token)
	if err != nil {
		return nil, err
	}

	if len(authMsg) != 0 {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(authMsg))
		return nil, nil
	}

	// The only way this can happen is if we get a request to <base>/<tenants>/<id>,
	// which we want to canonically redirect to <base>/<tenants>/<id>/
	if len(parts) < 3 {
		pathOffset := strings.TrimPrefix(req.URL.Path, p.BaseURL.Path)
		tenantHome := JoinPaths(p.BaseURL.String(), pathOffset) + "/"
		http.Redirect(w, req, tenantHome, http.StatusPermanentRedirect)
		return nil, nil
	}

	// The --static-prefix flag does not apply to the API, so we must manually trim it
	if strings.HasPrefix(parts[2], "api/") {
		req.URL.Path = parts[2]
	}

	return tenant, nil
}

func (p *ProxyState) GetAccessToken(r *http.Request) (string, bool) {
	token, ok := r.Header[p.Config.OIDC.AccessTokenHeader]
	if !ok || len(token) == 0 || len(token[0]) == 0 {
		return "", false
	}
	return token[0], true
}

func (p *ProxyState) ExtractClaims(r *http.Request) (token *jwt.Token, hasToken bool, err error) {
	accessToken, hasAccessToken := p.GetAccessToken(r)
	if !hasAccessToken {
		return nil, false, fmt.Errorf("No access or bearer token present")
	}
	hasToken = true
	tokenString := accessToken
	claims := make(jwt.MapClaims)
	// TODO: Deal with signature
	token, _, err = jwt.NewParser().ParseUnverified(tokenString, claims)
	return
}

func (p *ProxyState) MergeURLs(dest, src *url.URL) {
	dest.Scheme = src.Scheme
	dest.Opaque = src.Opaque
	dest.User = src.User
	dest.Host = src.Host
	dest.Path = src.Path + dest.Path
	if !strings.HasPrefix(dest.Path, "/") {
		dest.Path = "/" + dest.Path
	}
	dest.RawPath += src.RawPath
	dest.ForceQuery = src.ForceQuery
	destQuery, err := url.ParseQuery(dest.RawQuery)
	if err != nil {
		p.Log.Printf("Error parsing query, using empty query: %s\n", err)
	}
	srcQuery, err := url.ParseQuery(src.RawQuery)
	if err != nil {
		p.Log.Printf("Error parsing query, using empty query: %s\n", err)
	}
	for k, v := range srcQuery {
		destQuery[k] = v
	}
	dest.RawQuery = destQuery.Encode()
	dest.Fragment = src.Fragment
	dest.RawFragment = src.RawFragment
}

func (p *ProxyState) Authorize(req *http.Request, tenant *ProxyMLFlowTenant, token *jwt.Token) (string, error) {
	errBuilder := strings.Builder{}

	err := p.Config.OIDC.Policy.Inner.Execute(
		&errBuilder,
		PolicyContext{
			Token:   token,
			Request: req,
			Tenant:  tenant,
		},
	)

	if err != nil {
		return err.Error(), err
	}

	return strings.TrimSpace(errBuilder.String()), nil
}

func (p *ProxyState) Home(w http.ResponseWriter, req *http.Request, requestID string, token *jwt.Token) {
	var err error
	tenants := make([]*ProxyMLFlowTenant, 0, len(p.Tenants))
	for _, tenant := range p.Tenants {
		authMsg, err := p.Authorize(req, tenant.ProxyMLFlowTenant, token)
		if err != nil {
			p.InternalError(w, req, requestID, "checking tenant access for homepage", err)
			return
		}

		if len(authMsg) != 0 {
			continue
		}

		tenants = append(tenants, tenant.ProxyMLFlowTenant)
	}
	err = HomePage.Execute(w, map[string]interface{}{
		"tenants": tenants,
		"baseURL": p.BaseURL,
	})

	if err != nil {
		p.InternalError(w, req, requestID, "rendering homepage", err)
		return
	}
}

func (p *ProxyState) Proxy(w http.ResponseWriter, r *http.Request, requestID string, token *jwt.Token) {
	tenant, err := p.ValidateRequest(w, r, requestID, token)
	if err != nil {
		p.InternalError(w, r, requestID, "evaluating policy", err)
		return
	}
	p.Log.Printf("%s: Rewrote URL to %s\n", requestID, r.URL.String())

	if tenant == nil {
		return
	}
	tenant.ServeHTTP(w, r)
}

func (p *ProxyState) EnsureRequestID(w http.ResponseWriter, req *http.Request) string {
	requestUUID, err := uuid.NewRandom()
	if err != nil {
		p.InternalError(w, req, "<not yet assigned>", "generating request ID", err)
		return ""
	}
	return requestUUID.String()
}

func (p *ProxyState) EnsureToken(w http.ResponseWriter, req *http.Request, requestID string) *jwt.Token {
	token, hasToken, err := p.ExtractClaims(req)
	if !hasToken {
		p.Log.Printf("No token present, your authentication proxy setup is broken (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("No token was provided, contact your administrator. Request ID %s", requestID)))
		return nil

	}
	if err != nil {
		p.Log.Printf("Got invalid token (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Invalid token. Request ID %s", requestID)))
		return nil
	}
	p.Log.Printf("%s token=%v\n", req.URL.String(), token.Claims)
	return token
}

func (p *ProxyState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || r.URL.Path == p.LongHealthPath {
		w.WriteHeader(http.StatusOK)
		return
	}
	var requestID string
	defer func() {
		if err := recover(); err != nil {
			if requestID == "" {
				requestID = "<not yet assigned>"
			}
			p.Log.Printf("Request ID %s panicked: %v (%v)\n", requestID, err, r)
			p.Log.Printf("Request ID %s stack trace: \n%s", requestID, string(debug.Stack()))
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	requestID = p.EnsureRequestID(w, r)
	if requestID == "" {
		return
	}
	token := p.EnsureToken(w, r, requestID)
	if token == nil {
		return
	}
	if r.URL.Path == p.BasePath || r.URL.Path == p.TenantsPath || r.URL.Path == p.TenantsPath+"/" {
		http.Redirect(w, r, p.HomeURL, http.StatusPermanentRedirect)
		return
	}
	if r.URL.Path == p.BasePath+"/" {
		p.Home(w, r, requestID, token)
		return
	}
	if strings.HasPrefix(r.URL.Path, p.TenantsPath) {
		p.Proxy(w, r, requestID, token)
		return
	}
	w.WriteHeader(http.StatusNotFound)
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
