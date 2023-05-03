# MLFlow Multi-Tenant OIDC RBAC Proxy

This server acts as a reverse proxy to add Single Sign-On and Multi-Tenancy support to [MLFlow](https://mlflow.org/).

# This tool is still in early development, and experimental. Everything is subject to change. Use at your own risk.

## Design

This proxy is intended to be used with a separate MLFlow Tracking Server per "tenant", each listening on a separate static prefix, and each using an independent backing store and artifact store (though the same infrastructure can be used to provide these, such as using a single database instance to provide a separate database for each tenant).

This server proxies all of the tenant tracking servers, and applies a user-provided policy document that determines, based on the user's OIDC claims and the URL they are requesting, to forward or reject the request. This server does not implement OIDC itself, and instead expects itself to be proxied by another server, such as [this one](https://github.com/oauth2-proxy/oauth2-proxy), to provide it the user's JWT.

For using the tracking server web browser UI, OIDC is handled as normal. For API access, the user is expected to provide a "Direct Grant"-type OIDC client so that tenants are able to provide a JWT as a bearer token.

This server is 100% stateless, meaning multiple replicas can be deployed and load-balanced without additional configuration.


## Building

Needed tools:

* Go 1.16+ (1.18+ for running integration tests)
* Docker (Or compatible OCI image builder tool) (if building docker image)
* Kubectl, Helm, Kind (For running integration tests)

```bash
# Executable
go build -o proxy main.go
# Docker image
docker build -t ${your_registry}/meln5674/nexus-oidc-proxy:$(git rev-parse HEAD)
docker push ${your_registry}/meln5674/nexus-oidc-proxy:$(git rev-parse HEAD)
```

## Configuration

Configuration is set through a configuration file for non-sentive information, and environment variables for sensitive information

### Configuration File

```yaml
# HTTP server configuration
http:
  # Address and port to listen on
  # Defaults to 0.0.0.0:8080
  address: <hostname or ip>:<port>
  # The external URL this server is accessible to users at
  # Defaults to http://<address>, unless the host is 0.0.0.0,\
  # in which case it is swapped for "localhost"
  externalURL: http[s]://<external hostname>[:<port>][/<path>]
  # Path to serve tenants at.
  # This assumes all tenants (see below) have --static-prefix=<externalURL path>/<this path>/<tenant id>
  # This is concatenated with any path from externalURL (see above) when issuing static links
  # Defaults to /tenants/
  # tenantsPath: /<path>/
# TLS configuration
tls:
  # Set to true to serve using TLS (HTTPS)
  enabled: <true|false>
  # Path to your TLS certificate file
  certFile: </path/to/tls.crt>
  # Path to your TLS private key
  keyFile: </path/to/tls.key> 
# MLFlow tracking server configuration
mlflow:
  tenants:
    # The ID of the tenant. This must be a valid DNS label, much like kubernetes object names
  - id: tenant-name
    # A human-readable name or description of the tenant, which will appear in UI's
    name: Tenant Name
    # URL of the Upstream MLFlow server.
    # The --static-prefix for this server must match <http.externalURL path>/<http.tenantsPath>/<id>,
    # and the API must be accessible at <upstream>/api
    upstream: http[s]://<host>:<port>[/<base path>]
# OIDC authentication/authorization configuration
oidc:
  # Name of the HTTP header to expect the downstream proxy to set to the JWT OIDC Access token 
  # Defaults to X-Forwarded-Access-Token,
  # which is provided by OAuth2Proxy using --pass-access-token flag
  accessTokenHeader: <header name> 

  # A go template which validates that a user is allowed to perform a request within a tenant.
  # If the access should be denied, it must produce an error message (Or an HTML document with that 
  # error message) explaining the reason.
  # If the result is entirely whitespace (or empty), access is granted.
  # 
  # Variables provided:
  # .Token: See https://pkg.go.dev/github.com/golang-jwt/jwt/v4#section-readme
  # .Tenants: The list of tenants, (as provided in the field mlflow.tenants)
  # .Request A request object, see https://pkg.go.dev/net/http#Request for available fields
  # 
  # The default policy checks if a user has a Keycloak realm role matching the ID of the tenant
  # in question, and allows all requests if they do
  rbacPolicy: |-
    <template>
```

### Environment Variables

None currently.

### Command Line Arguments

#### --config <path>

Specify path the configuration file described above

### Trusted Certificates

If your MLFLow server use self-signed certificates or an internal certificate authority, this server must be set to trust them. This server is written in Go and uses [the standard locations](https://go.dev/src/crypto/x509/root_linux.go) for finding CA Certificate Bundles. Add your self-signed certificate or internal CA to one of these bundles to trust them.

### MLFlow Setup

This tool expects that each MLFlow tracking server is running as follows:

```bash
mlflow server \
  --static-prefix=<external URL path>/<tenants path>/<tenant ID> \ # See configuration section for these fields and how to set them
```

As well, each tenant tracking server must be using their own isolated backend store and artifact store for any isolation between tenants to take effect.

While techinically not required, it is highly recommened to also pass `--serving-artifacts` so that details of the artifact stores do not need to be distributed to tenants.

### Deploying

It is recommended to deploy this tool containerized, in a Kubernetes Cluster. A Dockerfile and [Helm chart](./deploy/helm/mlflow-oidc-proxy) are provided for doing so. An all-in-one chart capable of deploying a secure, resilient multi-tenant setup from scratch is provided [here](./deploy/helm/mlflow-multitenant).

See [here](./integration-test) for an example of this tool in action.

### Running Tests

```bash
./integration-test/run.sh
```
