# MLFlow Multi-Tenant OIDC RBAC Proxy

This server acts as a reverse proxy to add Single Sign-On and Multi-Tenancy support to [MLFlow](https://mlflow.org/).

### This tool is still in early development. Use at your own risk.

## Design

This proxy is intended to be used with a separate MLFlow Tracking Server per "tenant", each listening on a separate static prefix, and each using an independent backing store and artifact store (though the same infrastructure can be used to provide these, such as using a single database instance to provide a separate database for each tenant).

This server proxies all of the tenant tracking servers, and applies a user-provided policy document that determines, based on the user's OIDC claims and the URL they are requesting, to forward or reject the request. This server does not implement OIDC itself, and instead expects itself to be proxied by another server, such as [this one](https://github.com/oauth2-proxy/oauth2-proxy), to provide it the user's JWT.

For using the tracking server web browser UI, OIDC is handled as normal. For API access, the user is responsible for configuring their SSO provider and authenticating proxy to provide token support. See [this fork](https://github.com/meln5674/oauth2-proxy) of OAuth2 Proxy for an example of doing this using OAuth2 access or refresh tokens.

For automated access ("Non-Person Entities"), the server provides the ability to use "robot accounts". These work similarly to adding SSH public keys to a git repository, but instead work by associating a TLS certificate with a pre-made set of token claims. The private key can then be used with the MLFlow library, or with any HTTPS client library. These can be used to build models from whtin MLOps pipelines, or to retrieve a model from an automated model server.

This server is 100% stateless, meaning multiple replicas can be deployed and load-balanced without additional configuration.

## Deploying

Because of the number of moving parts required for a highly-available, reslient, multi-tenant deployment of MLFlow, it is highly recommended to use Kubernetes.

You have three major options for deploying:

1. Deploy all infrastructure yourself, either on bare metal or using the provided dockerfile
2. Deploy the proxy using the [standalone helm chart](./deploy/helm/mlflow-oidc-proxy)
3. Deploy an ["all-in-one" chart](./deploy/helm/mlflow-multitenant) that contains all components needed to go from zero to a secure, highly available, resilient, multitenant MLFlow deployment.

### Helm Charts

See [here](https://github.com/meln5674?tab=packages&repo_name=mlflow-oidc-proxy) for a list of current and valid versions

See the `values.yaml` [files for the charts](./deploy/helm) for documentation on the available options.

```bash
# Choose one:

# Standalone chart
helm install oci://ghcr.io/meln5674/mlflow-oidc-proxy/charts/mlflow-oidc-proxy --version ${version}

# Omnibus chart
# This first chart installs the operators that the second chart assumes are installed.
# It is optional if you already have compatible versions installed.
helm install oci://ghcr.io/meln5674/mlflow-oidc-proxy/charts/mlflow-multitenant-deps --version ${version}
helm install oci://ghcr.io/meln5674/mlflow-oidc-proxy/charts/mlflow-multitenant --version ${version}
```

### MLFlow Setup

This tool expects that each MLFlow tracking server is running as follows:

```bash
mlflow server \
  --static-prefix=<external URL path>/<tenants path>/<tenant ID> \ # See configuration section for these fields and how to set them
```

As well, each tenant tracking server must be using their own isolated backend store and artifact store for any isolation between tenants to take effect.

While techinically not required, it is highly recommened to also pass `--serving-artifacts` so that details of the artifact stores do not need to be distributed to tenants.


### Configuration

Configuration is set through a configuration file for non-sentive information, and environment variables for sensitive information

#### Configuration File

```yaml
# HTTP server configuration
http:
  # Address and port to listen on
  # Defaults to 0.0.0.0:8080
  address: <hostname or ip>:<port>
  # The external URL this server is accessible to users at
  # Defaults to http://<address>, unless the host is 0.0.0.0,
  # in which case it is swapped for "localhost"
  externalURL: http[s]://<external hostname>[:<port>][/<path>]
  # Path to serve tenants at.
  # This assumes all tenants have --static-prefix=<externalURL path>/<this path>/<tenant id>
  # This is concatenated with any path from externalURL (see above) when issuing static ui and ajax links
  # Defaults to /tenants/
  tenantsPath: /<path>/
# TLS configuration
tls:
  # Set to true to serve using TLS (HTTPS)
  enabled: <true|false>
  # Path to your TLS certificate file
  certFile: </path/to/tls.crt>
  # Path to your TLS private key
  keyFile: </path/to/tls.key> 
  # Set to true if another reverse proxy is terminating TLS (see robots below)
  terminated: <true|false>
# MLFlow tracking server configuration
mlflow:
  tenants:
    # The ID of the tenant. This must be a valid DNS label, much like kubernetes object names
  - id: tenant-name
    # A human-readable name or description of the tenant, which will appear in UI's
    name: Tenant Name
    # URL of the Upstream MLFlow server.
    # The --static-prefix for this server must match <http.externalURL path>/<http.tenantsPath>/<id>,
    #   and the API must be accessible at <upstream>/api
    upstream: http[s]://<host>:<port>[/<base path>]
# OIDC authentication/authorization configuration
oidc:
  # How to extract the JWT token from a request
  # * raw: Extract a raw header value (see tokenHeader)
  # * bearer: Extract the token using Bearer scheme authentication
  # * basic-user: Extract the token using the username from Basic scheme authentication (password is ignored)
  # * basic-password: Extract the token using the password from Basic scheme authentication (username is ignored)
  tokenMode: raw|bearer|basic-user|basic-password

  # Name of the HTTP header to use when using the 'raw' token mode (see tokenMode).
  # Ignored if not using the raw token mode.
  # Defaults to X-Forwarded-Access-Token,
  #   which is provided by OAuth2Proxy using --pass-access-token flag
  tokenHeader: <header name>

  # A go template which validates that a user is allowed to perform a request within a tenant.
  # If the access should be denied, it must produce an error message (Or an HTML document with that 
  # error message) explaining the reason.
  # If the result is entirely whitespace (or empty), access is granted.
  # See https://pkg.go.dev/text/template for syntax
  # This policy is also used to determine which tenants to display on the homepage by
  # checking access to the homepage of each MLFlow tenant server.
  # 
  # Variables provided:
  # .Token: See https://pkg.go.dev/github.com/golang-jwt/jwt/v4#section-readme
  # .Tenant: The tenant object provided in mlflow.tenants that matches the ID in the request URL
  # .Request: The incoming request being made, see https://pkg.go.dev/net/http#Request for available fields
  # .ExtraVariables: see oidc.extraVariables
  # 
  # The default policy checks if a user has a Keycloak realm role matching the ID of the tenant
  #   in question, and allows all requests if they do
  policy: |-
    <template>

  # A go template which extracts the "subject" (user) from a token. This value will injected as
  #   the user_id field and mlflow.user tag.
  # It is an error for this template to return an empty string.
  # See https://pkg.go.dev/text/template for syntax
  #
  # Variables provided:
  # .Token: See https://pkg.go.dev/github.com/golang-jwt/jwt/v4#section-readme
  # .ExtraVariables: see oidc.extraVariables
  #
  # The default extractor uses the Keycloak preferred_username claim
  getSubject: |-
    <template>

  # This value will be provided as the .ExtraVariables variable in the oidc.policy and oidc.getSubject
  #  templates. This can allow for embedding additional values to avoid needing to have contants or
  #  building data structures using sprig functions in your templates, for values such as group or
  #  role names, special users, etc.
  extraVariables: <any valid yaml>

# Robot accounts allow you to create fake users by assigning a static token to a TLS certificate 
# Because robots are implemented using TLS, either tls.enabled or tls.terminated must be true
robots:
  # When serving over plaintext (e.g, when TLS is terminated by ingress), this header
  #   is expected to contain the url-escaped certificate.
  # The reverse proxy is expected to validate that this ceritifcate is valid, this server
  #   only checks that it matches a provided robot certificate.
  # See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#client-certificate-authentication
  #   for how to enable this using the ingress nginx controller.
  # If using Kubernetes, you will need two ingresses or rules,
  #   one which routes to your authenticating proxy,
  #   and one which routes directly to this server and performs TLS client verification
  # Defaults to Ssl-Client-Cert, which is the header used by kubernetes ingress-nginx.
  certificateHeader: <Header-Name>
  # Robot users
  robots:
    # The name of the robot. Arbitrary, but used in debugging printouts
  - name: <name>
    # The path to the TLS certificate to verify the robot user
    certFile: </path/to/tls.crt>
    # The token claims
    token: 
      <claim>: <value>
      # ...
```

#### Extra Template functions

In addition to those provided by [sprig](https://masterminds.github.io/sprig/), the following additional functions are provided for use in policy templates:

##### intersection list1 list2 ...

Return the list of items which appear in every list.

Example: Find which of a set of roles a user has

`{{ intersection (list "role-1" "role-2") .Token.roles }}`

##### hasIntersection list1 list2 ...

Return true if any item appears in all lists. This is equivalent to `intersection list_of_lists | empty | not`,
however, it short circuits, returning true as soon as the first matching item is found.

Example: Check if a user has any of a set of roles

`{{ hasIntersection (list "role-1" "role-2") .Token.roles }}`

#### Environment Variables

None currently.

#### Command Line Arguments

#### `--config <path>`

Specify path the configuration file described above

#### Trusted Certificates

If your MLFLow servers use self-signed certificates or an internal certificate authority, this server must be set to trust them. This server is written in Go and uses [the standard locations](https://go.dev/src/crypto/x509/root_linux.go) for finding CA Certificate Bundles. Add your self-signed certificate or internal CA to one of these bundles to trust them. You can also set the variables documented in the previous link to set a specific file or directory containing trusted certificates. The provided Dockerfile uses the certificates that come with the official Golang image.


## Development

### Building

Needed tools:

* Go 1.19+
* GNU Make
* Docker (Or compatible OCI image builder tool) (if building docker image or running end-to-end tests)
* Kubectl, Helm, Kind (If running end-to-end tests)

#### Build Executable

```bash
make bin/mlflow-oidc-proxy
```

#### Build Docker image

```bash
# Docker image
docker build -t ${your_registry}/meln5674/mlflow-oidc-proxy:$(git rev-parse HEAD)
docker push ${your_registry}/meln5674/mlflow-oidc-proxy:$(git rev-parse HEAD)
```

### Unit Tests

```bash
# This will take about 30s to 1m on a 4-core machine

# This will open a new browser tab with the coverage report if tests succeed
make show-coverage

# This will just run the tests
make test
```

### End-to-End Tests

```bash
# This takes a substantial amount of time (30m to 45m on a 4-core machine)

# This will deploy a local KinD cluster, deploy a complete multi-tenant setup in two ways:
# * First, using the standalone chart
# * Second, using the omnibus chart
# Along with a jupyterhub instance, and execute a test notebook which trains a set of models,
# picks the best one, and then performs a REST request against a temporary server using that
# best model.
# This is done both by using an SSO-generated token, as well as a robot account.
# It also confirms that the run is correctly attributed to the correct user, and non-members
# cannot access the tenant.
make e2e

# If you want to watch the browser in action, and pause execution on failures
make e2e BILOBA_INTERACTIVE=true
```
