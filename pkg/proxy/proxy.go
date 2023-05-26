package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	"github.com/Masterminds/sprig"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	MLFlowUserTag     = "mlflow.user"
	MLFlowUserIDField = "user_id"
	MLFlowTagsField   = "tags"

	MLFlowCreateExperimentPath      = "2.0/mlflow/experiments/create"
	MLFlowCreateRunPath             = "2.0/mlflow/runs/create"
	MLFlowCreateRegisteredModelPath = "2.0/mlflow/registered-models/create"
	MLFlowCreateModelVersionPath    = "2.0/mlflow/model-versions/create"

	MLFlowSetTagExperimentPath      = "2.0/mlflow/experiments/set-experiment-tag"
	MLFlowSetTagRunPath             = "2.0/mlflow/runs/set-tag"
	MLFlowSetTagRegisteredModelPath = "2.0/mlflow/registered-models/set-tag"
	MLFlowSetTagModelVersionPath    = "2.0/mlflow/model-versions/set-tag"

	MLFlowDeleteTagRunPath             = "2.0/mlflow/runs/delete-tag"
	MLFlowDeleteTagRegisteredModelPath = "2.0/mlflow/registered-models/delete-tag"
	MLFlowDeleteTagModelVersionPath    = "2.0/mlflow/model-versions/delete-tag"

	MLFlowAPIPrefix  = "api/"
	MLFlowAJAXPrefix = "ajax-api/"
)

var (
	HomePage *template.Template
)

func init() {
	initHomePage()
	initDefaults()
}

func initHomePage() {
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
	Log          *log.Logger
	GetToken     TokenGetter
	RobotsByCert map[string]Robot

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
	var ok bool
	state.GetToken, ok = GetTokenGetter(config.OIDC.TokenMode, config.OIDC.TokenHeader)
	if !ok {
		return nil, fmt.Errorf("Invalid token mode: %s", config.OIDC.TokenMode)
	}
	if len(config.Robots.Robots) != 0 && !config.TLS.Enabled && !config.TLS.Terminated {
		return nil, fmt.Errorf("Robots require TLS. If this server has TLS terminated for it, set tls.terminated: true to silence this error")
	}
	state.RobotsByCert = make(map[string]Robot, len(config.Robots.Robots))
	for _, robot := range config.Robots.Robots {
		if robot.Cert.Raw == "" {
			return nil, fmt.Errorf("Robot %s is missing certPath", robot.Name)
		}
		derBase64 := base64.StdEncoding.EncodeToString(robot.Cert.Inner.Raw)
		state.RobotsByCert[derBase64] = robot
	}

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

func (p *ProxyState) ValidateRequest(w http.ResponseWriter, req *http.Request, requestID string, token *jwt.Token) (tenant *ProxyTenantState, path string, err error) {
	parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, p.BasePath+"/"), "/", 3)
	p.Log.Printf("Got request for %s (%v) for user %#v\n", req.URL.String(), parts, token)

	// This shouldn't be possible with how ServeHTTP works,
	// but this is here just in case to prevent panics
	if len(parts) < 2 {
		http.Redirect(w, req, p.HomeURL, http.StatusPermanentRedirect)
		return nil, "", nil
	}

	tenantID := parts[1]
	tenant, ok := p.Tenants[tenantID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(fmt.Sprintf("No such tenant: %s", tenantID)))
		return nil, "", nil
	}
	authMsg, err := p.Authorize(req, tenant.ProxyMLFlowTenant, token)
	if err != nil {
		return nil, "", err
	}

	if len(authMsg) != 0 {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(authMsg))
		return nil, "", nil
	}

	// The only way this can happen is if we get a request to <base>/<tenants>/<id>,
	// which we want to canonically redirect to <base>/<tenants>/<id>/
	if len(parts) < 3 {
		pathOffset := strings.TrimPrefix(req.URL.Path, p.BaseURL.Path)
		tenantHome := JoinPaths(p.BaseURL.String(), pathOffset) + "/"
		http.Redirect(w, req, tenantHome, http.StatusPermanentRedirect)
		return nil, "", nil
	}

	return tenant, parts[2], nil
}

type readCloserWithErrorChan struct {
	inner   io.ReadCloser
	errChan chan error
}

var _ = io.Reader(readCloserWithErrorChan{})

func (r readCloserWithErrorChan) Read(p []byte) (int, error) {
	err, ok := <-r.errChan
	if ok && err != nil {
		return 0, err
	}

	return r.inner.Read(p)
}

func (r readCloserWithErrorChan) Close() error {
	return r.inner.Close()
}

func mutateJSON(r io.ReadCloser, f func(map[string]interface{}) error) (io.ReadCloser, error) {
	r2, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	errChan := make(chan error)

	go func() {
		v := make(map[string]interface{})
		defer close(errChan)
		defer w.Close()
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			err, ok := r.(error)
			if ok {
				errChan <- err
				return
			}
			errChan <- fmt.Errorf("%v", r)
		}()
		err := json.NewDecoder(r).Decode(&v)
		if err != nil {
			f(nil)
			errChan <- err
			return
		}
		err = func() error {
			err = f(v)
			if err != nil {
				return err
			}
			err = json.NewEncoder(w).Encode(v)
			if err != nil {
				return err
			}
			return nil
		}()
		errChan <- err
	}()

	return readCloserWithErrorChan{
		inner:   r2,
		errChan: errChan,
	}, nil
}

func setUserID(subject string) func(map[string]interface{}) error {
	return func(body map[string]interface{}) error {
		if body == nil {
			return nil
		}
		body[MLFlowUserIDField] = subject
		return nil
	}
}

func setTagInList(tags []interface{}, key, value string) []interface{} {
	found := false
	for ix := range tags {
		tag := tags[ix].(map[string]interface{})
		if tag["key"] == key {
			tag["value"] = value
			tags[ix] = tag
			found = true
		}
	}
	if !found {
		tags = append(tags, map[string]interface{}{
			"key":   key,
			"value": value,
		})
	}
	return tags
}

func setUserTag(subject string) func(map[string]interface{}) error {
	return func(body map[string]interface{}) error {
		if body == nil {
			return nil
		}
		tags, ok := body[MLFlowTagsField].([]interface{})
		if !ok {
			tags = make([]interface{}, 0, 1)
		}
		body[MLFlowTagsField] = setTagInList(tags, MLFlowUserTag, subject)
		return nil
	}
}

func setUserValue(subject string) func(map[string]interface{}) error {
	return func(body map[string]interface{}) error {
		if body == nil {
			return nil
		}
		if body["key"] == MLFlowUserTag {
			body["value"] = subject
		}
		return nil
	}
}

func peekKey(keyChan chan string) func(map[string]interface{}) error {
	return func(body map[string]interface{}) error {
		defer close(keyChan)
		if body == nil {
			return nil
		}
		rawKey, ok := body["key"]
		if !ok {
			return nil
		}
		key, ok := rawKey.(string)
		if !ok {
			return nil
		}
		keyChan <- key
		return nil
	}
}

func (p *ProxyState) GetSubject(token *jwt.Token) (string, error) {
	s := strings.Builder{}
	err := p.Config.OIDC.GetSubject.Inner.Execute(&s, PolicyContext{
		Token: token,
	})
	if err != nil {
		return "", err
	}
	subject := s.String()
	if subject == "" {
		return "", fmt.Errorf("Subject template returned empty string")
	}
	return subject, nil
}

func (p *ProxyState) EnforceUserTagsAndFields(w http.ResponseWriter, req *http.Request, path string, requestID string, subject string, token *jwt.Token) (rejectMsg string, err error) {
	// Runs still have a deprecated non-tag field for the user id
	if path == MLFlowCreateRunPath {
		req.Body, err = mutateJSON(req.Body, setUserID(subject))
		if err != nil {
			return "", err
		}
		req.ContentLength = -1
	}

	switch path {
	case MLFlowCreateRunPath, MLFlowCreateExperimentPath, MLFlowCreateRegisteredModelPath, MLFlowCreateModelVersionPath:
		// Creating any taggable resource should set the user tag to the resolved username
		req.Body, err = mutateJSON(req.Body, setUserTag(subject))
		if err != nil {
			return "", err
		}
		req.ContentLength = -1

	case MLFlowSetTagRunPath,
		MLFlowSetTagExperimentPath,
		MLFlowSetTagRegisteredModelPath,
		MLFlowSetTagModelVersionPath,
		MLFlowDeleteTagRunPath,
		MLFlowDeleteTagRegisteredModelPath,
		MLFlowDeleteTagModelVersionPath:
		// Deleting the user tag is not allowed
		keyChan := make(chan string)

		req.Body, err = mutateJSON(req.Body, peekKey(keyChan))
		if err != nil {
			return "", err
		}
		req.ContentLength = -1

		for key := range keyChan {
			if key == MLFlowUserTag {
				return "Changing or removing the mlflow.user tag is not permitted in multi-tenant mode, please contact an administrator", nil
			}
		}
	}

	return "", nil
}

func (p *ProxyState) MutateRequest(w http.ResponseWriter, req *http.Request, path string, requestID string, subject string, token *jwt.Token) (rejectMsg string, err error) {
	if strings.HasPrefix(path, MLFlowAPIPrefix) {
		// The --static-prefix flag does not apply to the API, so we must manually trim it
		req.URL.Path = path
		apiPath := strings.TrimPrefix(path, MLFlowAPIPrefix)
		rejectMsg, err := p.EnforceUserTagsAndFields(w, req, apiPath, requestID, subject, token)
		if rejectMsg != "" || err != nil {
			return rejectMsg, err
		}
	}

	if strings.HasPrefix(path, MLFlowAJAXPrefix) {
		apiPath := strings.TrimPrefix(path, MLFlowAJAXPrefix)
		rejectMsg, err := p.EnforceUserTagsAndFields(w, req, apiPath, requestID, subject, token)
		if rejectMsg != "" || err != nil {
			return rejectMsg, err
		}
	}

	return "", nil
}

func (p *ProxyState) ExtractClaims(r *http.Request) (token *jwt.Token, hasToken bool, err error) {
	tokenString := p.GetToken(r)
	if tokenString == "" {
		return nil, false, nil
	}
	claims := make(jwt.MapClaims)
	// TODO: Deal with signature
	token, _, err = jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, true, err
	}
	return token, true, nil
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
	subject, err := p.GetSubject(token)
	if err != nil {
		p.InternalError(w, r, requestID, "determining subject", err)
		return
	}
	tenant, subPath, err := p.ValidateRequest(w, r, requestID, token)
	if err != nil {
		p.InternalError(w, r, requestID, "evaluating policy", err)
		return
	}
	rejectMsg, err := p.MutateRequest(w, r, subPath, requestID, subject, token)
	if err != nil {
		p.InternalError(w, r, requestID, "mutating request", err)
		return
	}
	if rejectMsg != "" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(rejectMsg))
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
	if !hasToken && err == nil {
		p.Log.Printf("Looking for robot cert, https: %v\n", p.Config.TLS.Enabled)
		robotCert, hasRobotCert, err2 := GetRobotCert(p.Config.Robots.CertificateHeader, p.Config.TLS.Enabled, req)
		err = err2
		if hasRobotCert && err == nil {
			derBase64 := base64.StdEncoding.EncodeToString(robotCert.Raw)
			robot, ok := p.RobotsByCert[derBase64]
			if ok {
				token = &robot.Token.Inner
				hasToken = true
			}
		}
	}
	if err != nil {
		p.Log.Printf("Got invalid token (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Invalid token. Request ID %s", requestID)))
		return nil
	}
	if !hasToken || token == nil {
		p.Log.Printf("No token present, your authentication proxy and/or tls termination setup is broken, or you provided an invalid robot certificate (Request ID: %s): %v\n", requestID, err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("No token was provided, contact your administrator. Request ID %s", requestID)))
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
