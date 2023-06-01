package main_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/meln5674/gingk8s"
	"github.com/meln5674/gosh"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMlflowOidcProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "mlflow-oidc-proxy Suite")
}

var (
	gk8s                    gingk8s.Gingk8s
	clusterID               gingk8s.ClusterID
	mlflowOIDCProxyImageID  gingk8s.CustomImageID
	jupyterhubImageID       gingk8s.CustomImageID
	oauth2ProxyImageID      gingk8s.CustomImageID
	kubectlImageID          gingk8s.ThirdPartyImageID
	keycloakImageID         gingk8s.ThirdPartyImageID
	redisImageID            gingk8s.ThirdPartyImageID
	mlflowImageID           gingk8s.ThirdPartyImageID
	kubeIngressProxyImageID gingk8s.ThirdPartyImageID
	nginxImageID            gingk8s.ThirdPartyImageID
	postgresImageIDs        gingk8s.ThirdPartyImageIDs
	certManagerImageIDs     gingk8s.ThirdPartyImageIDs
	minioImageIDs           gingk8s.ThirdPartyImageIDs
)

var _ = BeforeSuite(func(ctx context.Context) {
	var err error

	// The oauth2-proxy dockerfile assumes it is being built by docker buildx,
	// but we don't need that. Adding these two args at the top (and provding them
	// in the image build) works around this
	oauth2DockerfileBytes, err := os.ReadFile("modules/oauth2-proxy/Dockerfile")
	Expect(err).ToNot(HaveOccurred())
	oauth2Dockerfile := "ARG BUILDPLATFORM\nARG TARGETPLATFORM\n" + string(oauth2DockerfileBytes)
	Expect(os.WriteFile("modules/oauth2-proxy/Dockerfile", []byte(oauth2Dockerfile), 0x755))

	gk8s = gingk8s.ForSuite(GinkgoT())

	keycloakSetupScript, err = os.ReadFile("integration-test/keycloak-setup.sh")
	Expect(err).ToNot(HaveOccurred())

	dummyIngress, err = os.ReadFile("integration-test/dummy-ingress.yaml")
	Expect(err).ToNot(HaveOccurred())

	mlflowOIDCProxyImageID = gk8s.CustomImage(&mlflowOIDCProxyImage)

	jupyterhubImageID = gk8s.CustomImage(&jupyterhubImage)

	oauth2ProxyImageID = gk8s.CustomImage(&oauth2ProxyImage)

	kubectlImageID = gk8s.ThirdPartyImage(kubectlImage)

	keycloakImageID = gk8s.ThirdPartyImage(keycloakImage)

	redisImageID = gk8s.ThirdPartyImage(redisImage)

	mlflowImageID = gk8s.ThirdPartyImage(mlflowImage)

	kubeIngressProxyImageID = gk8s.ThirdPartyImage(kubeIngressProxyImage)

	nginxImageID = gk8s.ThirdPartyImage(nginxImage)

	postgresImageIDs = gk8s.ThirdPartyImages(postgresImages...)

	certManagerImageIDs = gk8s.ThirdPartyImages(certManagerImages...)

	minioImageIDs = gk8s.ThirdPartyImages(minioImages...)

	clusterID = gk8s.Cluster(&cluster,
		mlflowOIDCProxyImageID,
		jupyterhubImageID,
		oauth2ProxyImageID,
		kubectlImageID,
		keycloakImageID,
		redisImageID,
		mlflowImageID,
		kubeIngressProxyImageID,
		nginxImageID,
		postgresImageIDs,
		certManagerImageIDs,
		minioImageIDs,
	)

	gk8s.Release(clusterID, &kubeIngressProxy) // , ingressNginxID)

	gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)
	gk8s.ClusterAction(clusterID, "Watch Events", watchEvents)

	gk8s.Options(gingk8s.SuiteOpts{
		// NoSuiteCleanup: true,
	})
	gk8s.Setup(ctx)
})

var (
	cluster = gingk8s.KindCluster{
		Name:                   "mlflow-oidc-proxy",
		KindCommand:            gingk8s.DefaultKind,
		TempDir:                "integration-test",
		ConfigFilePath:         "integration-test/kind.config",
		ConfigFileTemplatePath: "integration-test/kind.config.template",
	}

	watchPods = &gingk8s.KubectlWatcher{
		Kind:  "pods",
		Flags: []string{"--all-namespaces"},
	}

	watchEvents = &gingk8s.KubectlWatcher{
		Kind:  "events",
		Flags: []string{"--all-namespaces"},
	}

	certManager = gingk8s.HelmRelease{
		Name: "cert-manager",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "jetstack",
					URL:  "https://charts.jetstack.io",
				},
				Name:    "cert-manager",
				Version: "v1.11.1",
			},
		},
		Set: gingk8s.Object{
			"installCRDs":        true,
			"prometheus.enabled": false,
		},
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/cert-manager",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/cert-manager-webhook",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/cert-manager-cainjector",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	certs = gingk8s.KubernetesManifests{
		Name: "Certificates",
		Resources: []string{
			`
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
`,
			`
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-cert
spec:
  commonName: '*.mlflow-oidc-proxy-it.cluster'
  secretName: test-cert
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
  dnsNames:
  - '*.mlflow-oidc-proxy-it.cluster'
  - keycloak.default.svc.cluster.local
  - postgres-postgres.default.svc.cluster.local
`,
			`
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: robot-1
spec:
  commonName: 'robot-1'
  secretName: robot-1
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
`,
			`
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: robot-2
spec:
  commonName: 'robot-2'
  secretName: robot-2
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
`,
		},

		Wait: []gingk8s.WaitFor{
			{
				Resource: "certificate/test-cert",
				For:      map[string]string{"condition": "ready"},
			},
		},
	}

	certsNoIssuer = gingk8s.KubernetesManifests{
		Name: "Certificates",
		Resources: []string{
			`
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-cert
spec:
  commonName: '*.mlflow-oidc-proxy-it.cluster'
  secretName: test-cert
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: mlflow-multitenant-ca
    kind: Issuer
    group: cert-manager.io
  dnsNames:
  - '*.mlflow-oidc-proxy-it.cluster'
`,
		},

		Wait: []gingk8s.WaitFor{
			{
				Resource: "certificate/test-cert",
				For:      map[string]string{"condition": "ready"},
			},
		},
	}

	ingressNginxBaseValues = gingk8s.NestedObject{
		"controller": gingk8s.Object{
			"service": gingk8s.Object{
				"type": "ClusterIP",
			},
			"kind": "DaemonSet",
			"hostPort": gingk8s.Object{
				"enabled": true,
			},
		},
	}

	ingressNginx = gingk8s.HelmRelease{
		Name: "ingress-nginx",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "ingress-nginx",
					URL:  "https://kubernetes.github.io/ingress-nginx",
				},
				Name:    "ingress-nginx",
				Version: "4.6.0",
			},
		},
		Values: []gingk8s.NestedObject{
			ingressNginxBaseValues,
			{
				"controller": gingk8s.Object{
					"extraArgs": gingk8s.Object{
						"default-ssl-certificate": "default/test-cert",
					},
				},
			},
		},
	}

	ingressNginx2 = gingk8s.HelmRelease{
		Name: "ingress-nginx",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "ingress-nginx",
					URL:  "https://kubernetes.github.io/ingress-nginx",
				},
				Name:    "ingress-nginx",
				Version: "4.6.0",
			},
		},
		Values: []gingk8s.NestedObject{
			ingressNginxBaseValues,
		},
	}

	kubeIngressProxy = gingk8s.HelmRelease{
		Name: "kube-ingress-proxy",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Name: "kube-ingress-proxy",
				Repo: &gingk8s.HelmRepo{
					Name: "kube-ingress-proxy",
					URL:  "https://meln5674.github.io/kube-ingress-proxy",
				},
				Version: "v0.3.0-rc1",
			},
		},
		Set: gingk8s.Object{
			"controllerAddresses[0].className": "nginx",
			"controllerAddresses[0].address":   "ingress-nginx-controller.default.svc.cluster.local",
			"hostPort.enabled":                 "true",
		},
		NoWait: true,
	}

	restartKubeIngressProxy = gingk8s.ClusterAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
		return g.KubectlRollout(ctx, cluster, gingk8s.ResourceReference{
			Name: "kube-ingress-proxy",
			Kind: "ds",
		}).Run()
	})

	postgresOperator = gingk8s.HelmRelease{
		Name: "postgres-operator",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Name: "postgres-operator",
				Repo: &gingk8s.HelmRepo{
					Name: "zalando",
					URL:  "https://opensource.zalando.com/postgres-operator/charts/postgres-operator",
				},
				Version: "1.10.0",
			},
		},
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/postgres-operator",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	postgres = gingk8s.KubernetesManifests{
		Name: "Postgresql Cluster",
		Resources: []string{
			`
apiVersion: "acid.zalan.do/v1"
kind: postgresql
metadata:
  name: postgres-postgres
spec:
  teamId: "postgres"
  numberOfInstances: 2
  users:  # Application/Robot users
    postgres:
    - superuser
    - createdb
    keycloak: []
    jupyterhub: []
    mlflow_tenant_1: []
    mlflow_tenant_2: []
  databases:
    keycloak: keycloak
    jupyterhub: jupyterhub
    mlflow_tenant_1: mlflow_tenant_1
    mlflow_tenant_2: mlflow_tenant_2
  postgresql:
    version: "14"

  volume:
    size: 4Gi
  # Custom TLS certificate. Disabled unless tls.secretName has a value.
  tls:
    secretName: "test-cert"  # should correspond to a Kubernetes Secret resource to load
    certificateFile: "tls.crt"
    privateKeyFile: "tls.key"
    caFile: "ca.crt"  # optionally configure Postgres with a CA certificate
  spiloFSGroup: 103
`,
		},
	}
	minio = gingk8s.HelmRelease{
		Name: "minio",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "minio",
					URL:  "https://charts.min.io/",
				},
				Name:    "minio",
				Version: "5.0.8",
			},
		},
		Set: minioSet(),
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/minio",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	postgresSecretsReady = gk8s.WaitForResourceExists(30*time.Second,
		gingk8s.ResourceReference{
			Name: "mlflow-tenant-2.postgres-postgres.credentials.postgresql.acid.zalan.do",
			Kind: "Secret",
		},
		gingk8s.ResourceReference{
			Name: "mlflow-tenant-1.postgres-postgres.credentials.postgresql.acid.zalan.do",
			Kind: "Secret",
		},
	)

	multitenantPostgresSecretsReady = gk8s.WaitForResourceExists(30*time.Second,
		gingk8s.ResourceReference{
			Name: "mlflow-tenant-2.mlflow-multitenant-postgres.credentials.postgresql.acid.zalan.do",
			Kind: "Secret",
		},
		gingk8s.ResourceReference{
			Name: "mlflow-tenant-1.mlflow-multitenant-postgres.credentials.postgresql.acid.zalan.do",
			Kind: "Secret",
		},
	)

	mlflow = []gingk8s.HelmRelease{
		{
			Name: "mlflow-tenant-1",
			Chart: &gingk8s.HelmChart{
				LocalChartInfo: gingk8s.LocalChartInfo{
					Path: "integration-test/mlflow",
				},
			},
			Set: mlflowSet(1),
			Wait: []gingk8s.WaitFor{
				{
					Resource: "deploy/mlflow-tenant-1",
					For:      map[string]string{"condition": "Available"},
				},
			},
		},

		gingk8s.HelmRelease{
			Name: "mlflow-tenant-2",
			Chart: &gingk8s.HelmChart{
				LocalChartInfo: gingk8s.LocalChartInfo{
					Path: "integration-test/mlflow",
				},
			},
			Set: mlflowSet(2),
			Wait: []gingk8s.WaitFor{
				{
					Resource: "deploy/mlflow-tenant-2",
					For:      map[string]string{"condition": "Available"},
				},
			},
		},
	}

	bitnamiRepo = gingk8s.HelmRepo{
		Name: "bitnami",
		URL:  "https://charts.bitnami.com/bitnami",
	}

	keycloak = gingk8s.HelmRelease{
		Name: "keycloak",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo:    &bitnamiRepo,
				Name:    "keycloak",
				Version: "14.2.0",
			},
		},
		Set: gingk8s.Object{
			"postgresql.enabled":                         false,
			"externalDatabase.host":                      "postgres-postgres",
			"externalDatabase.user":                      "keycloak",
			"externalDatabase.database":                  "keycloak",
			"externalDatabase.existingSecret":            "keycloak.postgres-postgres.credentials.postgresql.acid.zalan.do",
			"externalDatabase.existingSecretPasswordKey": "password",
			"ingress.enabled":                            true,
			"ingress.ingressClassName":                   "nginx",
			"ingress.hostname":                           "keycloak.mlflow-oidc-proxy-it.cluster",
			"ingress.extraTls[0].hosts[0]":               "keycloak.mlflow-oidc-proxy-it.cluster",
			`ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size`: "1m",
			"auth.adminUser":                  "admin",
			"auth.adminPassword":              "adminPassword",
			"tls.enabled":                     true,
			"tls.usePem":                      true,
			"tls.existingSecret":              "test-cert",
			"tls.keystorePassword":            "keystore-password",
			"tls.truststorePassword":          "truststore-password",
			"service.type":                    "ClusterIP",
			"extraVolumes[0].name":            "home",
			"extraVolumes[0].emptyDir.medium": "Memory",
			"extraVolumeMounts[0].name":       "home",
			"extraVolumeMounts[0].mountPath":  "/home/keycloak",
		},
		UpgradeFlags: []string{"--timeout=10m"},
	}

	mlflowOIDCProxyImage = gingk8s.CustomImage{
		Registry:   "local.host",
		Repository: "meln5674/mlflow-oidc-proxy",
		ContextDir: ".",
	}

	mlflowOIDCProxyConfigMapPath = "integration-test/mlflow-oidc-proxy-cfg-configmap.yaml"

	mlflowOIDCProxyConfig = gingk8s.KubernetesManifests{
		Name:          "MLFlow OIDC Proxy Config",
		ResourcePaths: []string{mlflowOIDCProxyConfigMapPath},
	}

	mlflowOIDCProxy = gingk8s.HelmRelease{
		Name: "mlflow-oidc-proxy",
		Chart: &gingk8s.HelmChart{
			LocalChartInfo: gingk8s.LocalChartInfo{
				Path: "deploy/helm/mlflow-oidc-proxy",
			},
		},
		Set: gingk8s.Object{
			"config.existingConfigMap.name": "mlflow-oidc-proxy",
			"image.pullPolicy":              "Never",
			"image.repository":              mlflowOIDCProxyImage.WithTag(""),
			"image.tag":                     gingk8s.DefaultExtraCustomImageTags[0],
			// "image.tag":                     gingk8s.DefaultCustomImageTag,

			"ingress.enabled":                  true,
			"ingress.hostname":                 "mlflow-api.mlflow-oidc-proxy-it.cluster",
			"ingress.tls.extraTLS[0].hosts[0]": "mlflow-api.mlflow-oidc-proxy-it.cluster",

			"config.yaml.robots.robots[0].name":                        "robot-1",
			"config.yaml.robots.robots[0].token.realm_access.roles[0]": "tenant-1",
			"config.yaml.robots.robots[0].token.preferred_username":    "robot-1",
			"config.yaml.robots.robots[0].secret.name":                 "robot-1",
			"config.yaml.robots.robots[0].secret.key":                  "tls.crt",
			"config.yaml.robots.robots[1].name":                        "robot-2",
			"config.yaml.robots.robots[1].token.realm_access.roles[0]": "tenant-2",
			"config.yaml.robots.robots[1].token.preferred_username":    "robot-2",
			"config.yaml.robots.robots[1].secret.name":                 "robot-2",
			"config.yaml.robots.robots[1].secret.key":                  "tls.crt",
		},
		SetString: gingk8s.StringObject{
			"ingress.className": "nginx",
			`ingress.annotations.nginx\.ingress\.kubernetes\.io/auth-tls-pass-certificate-to-upstream`: "true",
			`ingress.annotations.nginx\.ingress\.kubernetes\.io/auth-tls-verify-client`:                "optional_no_ca",
			`ingress.annotations.nginx\.ingress\.kubernetes\.io/auth-tls-secret`:                       `default/test-cert`,
		},
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/mlflow-oidc-proxy",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	oauth2ProxyConfigMapPath = "integration-test/oauth2-proxy-cfg-configmap.yaml"

	oauth2ProxyConfig = gingk8s.KubernetesManifests{
		Name:          "OAuth2 Proxy Config",
		ResourcePaths: []string{oauth2ProxyConfigMapPath},
	}

	oauth2ProxyImage = gingk8s.CustomImage{
		Registry:   "local.host/mlflow-oidc-proxy",
		Repository: "oauth2-proxy",
		Dockerfile: "modules/oauth2-proxy/Dockerfile",
		ContextDir: "modules/oauth2-proxy",
		BuildArgs: map[string]string{
			"BUILDPLATFORM":  "linux/amd64",
			"TARGETPLATFORM": "linux/amd64",
		},
	}

	oauth2Proxy = gingk8s.HelmRelease{
		Name: "oauth2-proxy",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo:    &bitnamiRepo,
				Name:    "oauth2-proxy",
				Version: "3.5.0",
			},
		},
		Set: gingk8s.Object{
			"ingress.enabled":                   true,
			"ingress.ingressClassName":          "nginx",
			"ingress.hostname":                  "mlflow.mlflow-oidc-proxy-it.cluster",
			"ingress.extraTls[0].hosts[0]":      "keycloak.mlflow-oidc-proxy-it.cluster",
			"configuration.clientID":            "mlflow",
			"configuration.clientSecret":        getKeycloakClientSecret("mlflow"),
			"configuration.cookieSecret":        "SbeldwDCUmzHdHGu8j61j6I2fnPjCxyP",
			"configuration.existingConfigmap":   "oauth2-proxy-cfg",
			"configuration.sessionStoreType":    "redis",
			"extraVolumes[0].name":              "provider-ca",
			"extraVolumes[0].secret.secretName": "test-cert",
			"extraVolumeMounts[0].name":         "provider-ca",
			"extraVolumeMounts[0].mountPath":    "/var/run/secrets/test-certs/ca.crt",
			"extraVolumeMounts[0].subPath":      "ca.crt",
			"hostAliases[0].ip":                 getIngressControllerIP,
			"hostAliases[0].hostnames[0]":       "keycloak.mlflow-oidc-proxy-it.cluster",
			"image.registry":                    "local.host",
			"image.repository":                  "mlflow-oidc-proxy/oauth2-proxy",
			"image.tag":                         gingk8s.DefaultExtraCustomImageTags[0],
			"image.pullPolicy":                  "Never",
		},
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/oauth2-proxy",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	jupyterhubImage = gingk8s.CustomImage{
		Registry:   "local.host",
		Repository: "mlflow-oidc-proxy/jupyterhub-singleuser",
		Dockerfile: "integration-test/jupyterhub.Dockerfile",
	}

	mlflowMultitenantDeps = gingk8s.HelmRelease{
		Name: "mlflow-multitenant-deps",
		Chart: &gingk8s.HelmChart{
			LocalChartInfo: gingk8s.LocalChartInfo{
				Path:             "deploy/helm/mlflow-multitenant-deps",
				DependencyUpdate: true,
			},
		},
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/mlflow-multitenant-deps-cert-manager",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/mlflow-multitenant-deps-cert-manager-webhook",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/mlflow-multitenant-deps-cert-manager-cainjector",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/mlflow-multitenant-deps-postgres-operator",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	mlflowMultitenant = gingk8s.HelmRelease{
		Name: "mlflow-multitenant",
		Chart: &gingk8s.HelmChart{
			LocalChartInfo: gingk8s.LocalChartInfo{
				Path:             "deploy/helm/mlflow-multitenant",
				DependencyUpdate: true,
			},
		},
		ValuesFiles:  []string{"deploy/helm/mlflow-multitenant/values.yaml"},
		UpgradeFlags: []string{"--wait-for-jobs", "--timeout=30m"},
		SetFile: gingk8s.StringObject{
			"oauth2-proxy.configuration.extraContent": "integration-test/cases/refresh_access/oauth2_proxy.cfg",
			"mlflow-oidc-proxy.config.content":        "integration-test/cases/refresh_access/mlflow-oidc-proxy.cfg",
		},
		SetString: gingk8s.StringObject{
			"mlflow-oidc-proxy.ingress.className": "nginx",
			`mlflow-oidc-proxy.ingress.annotations.nginx\.ingress\.kubernetes\.io/auth-tls-pass-certificate-to-upstream`: "true",
			`mlflow-oidc-proxy.ingress.annotations.nginx\.ingress\.kubernetes\.io/auth-tls-verify-client`:                "optional_no_ca",
			`mlflow-oidc-proxy.ingress.annotations.nginx\.ingress\.kubernetes\.io/auth-tls-secret`:                       `default/mlflow-multitenant-ca`,
		},
		Set: gingk8s.Object{
			"keycloak.ingress.enabled":              true,
			"keycloak.ingress.ingressClassName":     "nginx",
			"keycloak.ingress.hostname":             "keycloak.mlflow-oidc-proxy-it.cluster",
			"keycloak.ingress.extraTls[0].hosts[0]": "keycloak.mlflow-oidc-proxy-it.cluster",
			`keycloak.ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size`: "1m",
			"keycloak.tls.keystorePassword":            "keystore-password",
			"keycloak.tls.truststorePassword":          "truststore-password",
			"keycloak.service.type":                    "ClusterIP",
			"keycloak.auth.adminUser":                  "admin",
			"keycloak.auth.adminPassword":              "adminPassword",
			"keycloak.extraVolumes[0].name":            "home",
			"keycloak.extraVolumes[0].emptyDir.medium": "Memory",
			"keycloak.extraVolumeMounts[0].name":       "home",
			"keycloak.extraVolumeMounts[0].mountPath":  "/home/keycloak",

			"oauth2-proxy.ingress.enabled":                true,
			"oauth2-proxy.ingress.ingressClassName":       "nginx",
			"oauth2-proxy.ingress.hostname":               "mlflow.mlflow-oidc-proxy-it.cluster",
			"oauth2-proxy.ingress.extraTls[0].hosts[0]":   "mlflow.mlflow-oidc-proxy-it.cluster",
			"oauth2-proxy.configuration.sessionStoreType": "redis",
			"oauth2-proxy.image.registry":                 "local.host",
			"oauth2-proxy.image.repository":               "mlflow-oidc-proxy/oauth2-proxy",
			"oauth2-proxy.image.tag":                      gingk8s.DefaultExtraCustomImageTags[0],
			"oauth2-proxy.image.pullPolicy":               "Never",
			"oauth2-proxy.hostAliases[0].ip":              getIngressControllerIP,
			"oauth2-proxy.hostAliases[0].hostnames[0]":    "keycloak.mlflow-oidc-proxy-it.cluster",

			"mlflow-oidc-proxy.image.pullPolicy": "Never",
			"mlflow-oidc-proxy.image.repository": mlflowOIDCProxyImage.WithTag(""),
			"mlflow-oidc-proxy.image.tag":        gingk8s.DefaultExtraCustomImageTags[0],
			//"mlflow-oidc-proxy.image.tag":        gingk8s.DefaultCustomImageTag,
			"mlflow-oidc-proxy.config.yaml.tls.terminated":                               true,
			"mlflow-oidc-proxy.config.yaml.robots.robots[0].name":                        "robot-1",
			"mlflow-oidc-proxy.config.yaml.robots.robots[0].token.realm_access.roles[0]": "tenant-1",
			"mlflow-oidc-proxy.config.yaml.robots.robots[0].token.preferred_username":    "robot-1",
			"mlflow-oidc-proxy.config.yaml.robots.robots[1].name":                        "robot-2",
			"mlflow-oidc-proxy.config.yaml.robots.robots[1].token.realm_access.roles[0]": "tenant-2",
			"mlflow-oidc-proxy.config.yaml.robots.robots[1].token.preferred_username":    "robot-2",
			"mlflow-oidc-proxy.ingress.enabled":                                          true,
			"mlflow-oidc-proxy.ingress.hostname":                                         "mlflow-api.mlflow-oidc-proxy-it.cluster",

			"keycloakJob.extraClients[0].id":          "jupyterhub",
			"keycloakJob.extraClients[0].secretName":  "mlflow-multitenant-jupyterhub-oidc",
			"keycloakJob.extraClients[0].callbackURL": "https://jupyterhub.mlflow-oidc-proxy-it.cluster/hub/oauth_callback",

			"postgres.extraUsers.jupyterhub[0]":  "login",
			"postgres.extraDatabases.jupyterhub": "jupyterhub",

			"mlflow.tenants[0].id":   "tenant-1",
			"mlflow.tenants[0].name": "Tenant 1",
			"mlflow.tenants[1].id":   "tenant-2",
			"mlflow.tenants[1].name": "Tenant 2",

			"minio.resources.requests.memory": "250Mi",
		},
	}

	mlflowMultitenantDefaults = gingk8s.HelmRelease{
		Name: "mlflow-multitenant",
		Chart: &gingk8s.HelmChart{
			LocalChartInfo: gingk8s.LocalChartInfo{
				Path:             "deploy/helm/mlflow-multitenant",
				DependencyUpdate: true,
			},
		},
		UpgradeFlags: []string{"--wait-for-jobs", "--timeout=30m"},
		Set: gingk8s.Object{
			"mlflow-oidc-proxy.image.repository": mlflowOIDCProxyImage.WithTag(""),
			"mlflow-oidc-proxy.image.tag":        gingk8s.DefaultExtraCustomImageTags[0],
			"keycloak.service.type":              "ClusterIP",
		},
	}

	jupyterhubBaseSet = gingk8s.Object{
		"proxy.service.type":       "ClusterIP",
		"ingress.enabled":          "true",
		"ingress.hosts[0]":         "jupyterhub.mlflow-oidc-proxy-it.cluster",
		"ingress.ingressClassName": "nginx",
		"ingress.tls[0].hosts[0]":  "jupyterhub.mlflow-oidc-proxy-it.cluster",
		"hub.db.type":              "postgres",

		"hub.db.upgrade": "true",
		"hub.config.JupyterHub.authenticator_class":           "oauthenticator.generic.GenericOAuthenticator",
		"hub.config.GenericOAuthenticator.oauth_callback_url": "https://jupyterhub.mlflow-oidc-proxy-it.cluster/hub/oauth_callback",
		"hub.config.GenericOAuthenticator.scope[0]":           "openid",
		"hub.config.GenericOAuthenticator.scope[1]":           "profile",
		"hub.config.GenericOAuthenticator.username_key":       "preferred_username",
		"hub.config.GenericOAuthenticator.client_id":          "jupyterhub",
		"hub.config.GenericOAuthenticator.login_service":      "Keycloak",
		"hub.extraEnv.http_proxy":                             "http://kube-ingress-proxy:80",
		"hub.extraEnv.https_proxy":                            "http://kube-ingress-proxy:80",
		"hub.extraEnv.no_proxy":                               "localhost",
		"hub.extraVolumes[0].name":                            "tls",
		"hub.extraVolumeMounts[0].name":                       "tls",
		"hub.extraVolumeMounts[0].mountPath":                  "/etc/ssl/certs/ca-certificates.crt",
		"hub.extraVolumeMounts[0].subPath":                    "ca.crt",
		"singleuser.image.name":                               jupyterhubImage.WithTag(""),
		"singleuser.image.tag":                                gingk8s.DefaultCustomImageTag,
		"singleuser.extraEnv.http_proxy":                      "http://kube-ingress-proxy:80",
		"singleuser.extraEnv.https_proxy":                     "http://kube-ingress-proxy:80",
		"singleuser.extraEnv.no_proxy":                        "localhost",
		"singleuser.storage.extraVolumes[0].name":             "tls",
		"singleuser.storage.extraVolumeMounts[0].name":        "tls",
		"singleuser.storage.extraVolumeMounts[0].mountPath":   "/etc/ssl/certs/ca-certificates.crt",
		"singleuser.storage.extraVolumeMounts[0].subPath":     "ca.crt",
		"singleuser.storage.extraVolumes[1].name":             "src",
		"singleuser.storage.extraVolumes[1].hostPath.type":    "Directory",
		"singleuser.storage.extraVolumes[1].hostPath.path":    "/mnt/host/mlflow-oidc-proxy",
		"singleuser.storage.extraVolumeMounts[1].name":        "src",
		"singleuser.storage.extraVolumeMounts[1].mountPath":   "/mnt/host/mlflow-oidc-proxy",
	}

	jupyterhub = gingk8s.HelmRelease{
		Name: "jupyterhub",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "jupyterhub",
					URL:  "https://jupyterhub.github.io/helm-chart/",
				},
				Name:    "jupyterhub",
				Version: "2.0.0",
			},
		},
		Set: jupyterhubBaseSet.MergedFrom(gingk8s.Object{
			"hub.config.GenericOAuthenticator.client_secret":       getKeycloakClientSecret("jupyterhub"),
			"hub.extraVolumes[0].secret.secretName":                "test-cert",
			"singleuser.storage.extraVolumes[0].secret.secretName": "test-cert",
			"hub.db.password": func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
				var password string
				err := g.KubectlGetSecretValue(ctx, cluster, "jupyterhub.postgres-postgres.credentials.postgresql.acid.zalan.do", "password", &password).Run()
				return password, err
			},
			"hub.db.url": "postgresql+psycopg2://jupyterhub@postgres-postgres:5432/jupyterhub?sslmode=require",
			"hub.config.GenericOAuthenticator.userdata_url":  "https://keycloak.mlflow-oidc-proxy-it.cluster/realms/integration-test/protocol/openid-connect/userinfo",
			"hub.config.GenericOAuthenticator.token_url":     "https://keycloak.mlflow-oidc-proxy-it.cluster/realms/integration-test/protocol/openid-connect/token",
			"hub.config.GenericOAuthenticator.authorize_url": "https://keycloak.mlflow-oidc-proxy-it.cluster/realms/integration-test/protocol/openid-connect/auth",
		}),
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/hub",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/proxy",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	jupyterhub2 = gingk8s.HelmRelease{
		Name: "jupyterhub",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Repo: &gingk8s.HelmRepo{
					Name: "jupyterhub",
					URL:  "https://jupyterhub.github.io/helm-chart/",
				},
				Name:    "jupyterhub",
				Version: "2.0.0",
			},
		},
		Set: jupyterhubBaseSet.MergedFrom(gingk8s.Object{
			"hub.config.GenericOAuthenticator.client_secret": func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) string {
				return g.KubectlReturnSecretValue(ctx, cluster, "mlflow-multitenant-jupyterhub-oidc", "client-secret")
			},
			"ingress.tls[0].secretName":                            "test-cert",
			"hub.db.url":                                           "postgresql+psycopg2://jupyterhub@mlflow-multitenant-postgres:5432/jupyterhub?sslmode=require",
			"hub.extraVolumes[0].secret.secretName":                "mlflow-multitenant-ca",
			"singleuser.storage.extraVolumes[0].secret.secretName": "mlflow-multitenant-ca",
			"hub.db.password": func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
				var password string
				err := g.KubectlGetSecretValue(ctx, cluster, "jupyterhub.mlflow-multitenant-postgres.credentials.postgresql.acid.zalan.do", "password", &password).Run()
				return password, err
			},
			"hub.config.GenericOAuthenticator.userdata_url":  "https://keycloak.mlflow-oidc-proxy-it.cluster/realms/mlflow-multitenant/protocol/openid-connect/userinfo",
			"hub.config.GenericOAuthenticator.token_url":     "https://keycloak.mlflow-oidc-proxy-it.cluster/realms/mlflow-multitenant/protocol/openid-connect/token",
			"hub.config.GenericOAuthenticator.authorize_url": "https://keycloak.mlflow-oidc-proxy-it.cluster/realms/mlflow-multitenant/protocol/openid-connect/auth",
		}),
		Wait: []gingk8s.WaitFor{
			{
				Resource: "deploy/hub",
				For:      map[string]string{"condition": "Available"},
			},
			{
				Resource: "deploy/proxy",
				For:      map[string]string{"condition": "Available"},
			},
		},
	}

	kubectlImage          = &gingk8s.ThirdPartyImage{Name: "docker.io/bitnami/kubectl:1.25.3"}
	keycloakImage         = &gingk8s.ThirdPartyImage{Name: "docker.io/bitnami/keycloak:21.0.2-debian-11-r0"}
	redisImage            = &gingk8s.ThirdPartyImage{Name: "docker.io/bitnami/redis:7.0.10-debian-11-r4"}
	mlflowImage           = &gingk8s.ThirdPartyImage{Name: "ghcr.io/mlflow/mlflow:v2.3.2"}
	kubeIngressProxyImage = &gingk8s.ThirdPartyImage{Name: "ghcr.io/meln5674/kube-ingress-proxy:v0.3.0-rc1"}
	postgresImages        = []*gingk8s.ThirdPartyImage{
		&gingk8s.ThirdPartyImage{Name: "ghcr.io/zalando/spilo-15:3.0-p1"},
		&gingk8s.ThirdPartyImage{Name: "registry.opensource.zalan.do/acid/postgres-operator:v1.10.0"},
	}
	certManagerImages = []*gingk8s.ThirdPartyImage{
		&gingk8s.ThirdPartyImage{Name: "quay.io/jetstack/cert-manager-cainjector:v1.11.1"},
		&gingk8s.ThirdPartyImage{Name: "quay.io/jetstack/cert-manager-controller:v1.11.1"},
		&gingk8s.ThirdPartyImage{Name: "quay.io/jetstack/cert-manager-webhook:v1.11.1"},
	}
	nginxImage  = &gingk8s.ThirdPartyImage{Name: "registry.k8s.io/ingress-nginx/controller:v1.7.0"}
	minioImages = []*gingk8s.ThirdPartyImage{
		&gingk8s.ThirdPartyImage{Name: "quay.io/minio/mc:RELEASE.2023-04-12T02-21-51Z"},
		&gingk8s.ThirdPartyImage{Name: "quay.io/minio/minio:RELEASE.2023-04-13T03-08-07Z"},
	}
)

func restartOAuth2Proxy(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
	return gosh.And(
		g.Kubectl(ctx, cluster, "rollout", "restart", "deploy/oauth2-proxy"),
		g.Kubectl(ctx, cluster, "rollout", "status", "deploy/oauth2-proxy"),
	).Run()
}

var (
	dummyIngress []byte // set during BeforeSuite
)

func getIngressControllerIP(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
	var ip string
	err := g.Kubectl(ctx, cluster, "get", "svc", "ingress-nginx-controller", "--template", "{{ .spec.clusterIP }}").
		WithStreams(gosh.FuncOut(gosh.SaveString(&ip))).
		Run()
	return ip, err
}

func waitForIngressWebhook(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
	// For whatever reason, even after the ingress controll reports as "healthy", creating an ingress for the first few seconds after the chart finishes results in an error.
	// This loop waits for this to not be the case
	defer g.Kubectl(ctx, cluster, "delete", "ingress", "sentinel").Run()
	for {
		err := g.Kubectl(ctx, cluster, "create", "-f", "-").
			WithStreams(gosh.BytesIn(dummyIngress)).
			Run()
		if errors.Is(err, context.Canceled) {
			return err
		}
		if err == nil {
			return nil
		}
		GinkgoWriter.Printf("Failed to create sentinel ingress: %v\n", err)
		time.Sleep(15 * time.Second)
	}
}

func getKeycloakClientSecret(clientID string) func(gingk8s.Gingk8s, context.Context, gingk8s.Cluster) (string, error) {
	return func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
		var clientSecret string
		err := g.KubectlExec(ctx, cluster, "keycloak-0", "cat", []string{"/tmp/client-secrets/" + clientID}).
			WithStreams(gosh.FuncOut(gosh.SaveString(&clientSecret))).
			Run()
		clientSecret = strings.TrimSuffix(clientSecret, "\n")
		return clientSecret, err
	}
}

func oauth2ProxySetup(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
	fYAML, err := os.Create(oauth2ProxyConfigMapPath)
	if err != nil {
		return err
	}
	defer fYAML.Close()

	_, err = fYAML.Write([]byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: oauth2-proxy-cfg
data:
  oauth2_proxy.cfg: |
`))

	fCfg, err := os.Open("integration-test/cases/access_id/oauth2_proxy.cfg")
	if err != nil {
		return err
	}
	defer fCfg.Close()
	scanner := bufio.NewScanner(fCfg)
	for scanner.Scan() {
		_, err = fYAML.Write([]byte("\n    "))
		if err != nil {
			return err
		}
		_, err = fYAML.Write(scanner.Bytes())
		if err != nil {
			return err
		}
	}
	return scanner.Err()
}

func mlflowOIDCProxySetup(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
	fYAML, err := os.Create(mlflowOIDCProxyConfigMapPath)
	if err != nil {
		return err
	}
	defer fYAML.Close()

	_, err = fYAML.Write([]byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: mlflow-oidc-proxy
data:
  mlflow-oidc-proxy.cfg: |
`))

	fCfg, err := os.Open("integration-test/cases/access_id/mlflow-oidc-proxy.cfg")
	if err != nil {
		return err
	}
	defer fCfg.Close()
	scanner := bufio.NewScanner(fCfg)
	for scanner.Scan() {
		_, err = fYAML.Write([]byte("\n    "))
		if err != nil {
			return err
		}
		_, err = fYAML.Write(scanner.Bytes())
		if err != nil {
			return err
		}
	}
	return scanner.Err()
}

var (
	keycloakSetupScript []byte // Set during BeforeSuite
)

func keycloakSetup(pod string, extraEnv ...string) func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
	fullScriptParts := make([]string, len(extraEnv))
	copy(fullScriptParts, extraEnv)
	fullScriptParts = append(fullScriptParts, string(keycloakSetupScript))
	return func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
		return g.KubectlExec(ctx, cluster, pod, "bash", []string{"-xe"}).
			WithStreams(gosh.StringIn(strings.Join(fullScriptParts, "\n"))).
			Run()
	}
}

func minioSet() gingk8s.Object {
	set := gingk8s.Object{
		"resources.requests.memory":       "512Mi",
		"replicas":                        "1",
		"persistence.enabled":             false,
		"mode":                            "standalone",
		"consoleIngress.enabled":          true,
		"consoleIngress.hosts[0]":         "minio-console.mlflow-oidc-proxy-it.cluster",
		"consoleIngress.ingressClassName": "nginx",
		"consoleIngress.tls[0].hosts[0]":  "minio-console.mlflow-oidc-proxy-it.cluster",
		"rootUser":                        "rootuser",
		"rootPassword":                    "rootpassword",
	}

	for ix, tenant := range []int{1, 2} {
		set[fmt.Sprintf("users[%d].accessKey", ix)] = fmt.Sprintf("tenant%d", tenant)
		set[fmt.Sprintf("users[%d].secretKey", ix)] = fmt.Sprintf("tenant%dpassword", tenant)
		set[fmt.Sprintf("users[%d].policy", ix)] = fmt.Sprintf("mlflow-tenant-%d", tenant)
		set[fmt.Sprintf("buckets[%d].name", ix)] = fmt.Sprintf("mlflow-tenant-%d", tenant)
		set[fmt.Sprintf("policies[%d].name", ix)] = fmt.Sprintf("mlflow-tenant-%d", tenant)
		set[fmt.Sprintf("policies[%d].statements[0].resources[0]", ix)] = fmt.Sprintf("arn:aws:s3:::mlflow-tenant-%d", tenant)
		set[fmt.Sprintf("policies[%d].statements[0].actions", ix)] = []string{"s3:ListBucket"}
		set[fmt.Sprintf("policies[%d].statements[1].resources[0]", ix)] = fmt.Sprintf("arn:aws:s3:::mlflow-tenant-%d/*", tenant)
		set[fmt.Sprintf("policies[%d].statements[1].actions", ix)] = []string{"s3:PutObject", "s3:GetObject", "s3:DeleteObject"}
	}

	return set
}

func mlflowSet(tenant int) gingk8s.Object {

	psqlTenantSecretName := fmt.Sprintf("mlflow-tenant-%d.postgres-postgres.credentials.postgresql.acid.zalan.do", tenant)
	psqlURI := fmt.Sprintf("postgresql+psycopg2://$(DATABASE_USER):$(DATABASE_PASSWORD)@postgres-postgres:5432/mlflow_tenant_%d?sslmode=require", tenant)

	return gingk8s.Object{
		"env[0].name":  "MLFLOW_S3_ENDPOINT_URL",
		"env[0].value": "http://minio:9000",
		"env[1].name":  "AWS_ACCESS_KEY_ID",
		"env[1].value": fmt.Sprintf("tenant%d", tenant),
		"env[2].name":  "AWS_SECRET_ACCESS_KEY",
		"env[2].value": fmt.Sprintf("tenant%dpassword", tenant),
		"env[3].name":  "DATABASE_USER",
		"env[3].value": func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
			var username string
			err := g.KubectlGetSecretValue(ctx, cluster, psqlTenantSecretName, "username", &username).Run()
			return username, err
		},
		"env[4].name": "DATABASE_PASSWORD",
		"env[4].value": func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) (string, error) {
			var password string
			err := g.KubectlGetSecretValue(ctx, cluster, psqlTenantSecretName, "password", &password).Run()
			return password, err
		},
		"args[0]": "--backend-store-uri=" + psqlURI,
		"args[1]": "--serve-artifacts",
		"args[2]": fmt.Sprintf("--artifacts-destination=s3://mlflow-tenant-%d/", tenant),
		"args[3]": "--default-artifact-root=mlflow-artifacts:/",

		"staticPrefix":                 fmt.Sprintf("/tenants/tenant-%d", tenant),
		"requirements.psycopg2-binary": "",
		"requirements.boto3":           "",
	}
}
