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

	"github.com/chromedp/chromedp"
	"github.com/meln5674/gingk8s"
	"github.com/meln5674/gosh"
	"github.com/onsi/biloba"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMlflowOidcProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "mlflow-oidc-proxy Suite")
}

var b *biloba.Biloba

var gk8s gingk8s.Gingk8s

var _ = BeforeSuite(func(ctx context.Context) {
	var err error

	gk8s = gingk8s.ForSuite()

	keycloakSetupScript, err = os.ReadFile("integration-test/keycloak-setup.sh")
	Expect(err).ToNot(HaveOccurred())

	dummyIngress, err = os.ReadFile("integration-test/dummy-ingress.yaml")
	Expect(err).ToNot(HaveOccurred())

	mlflowOIDCProxyImageID := gk8s.CustomImage(&mlflowOIDCProxyImage)

	jupyterhubImageID := gk8s.CustomImage(&jupyterhubImage)

	oauth2ProxyImageID := gk8s.ThirdPartyImage(&oauth2ProxyImage)

	clusterID := gk8s.Cluster(&cluster,
		mlflowOIDCProxyImageID, jupyterhubImageID,
		oauth2ProxyImageID, // TODO: Add third party images for everything else
	)

	gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)

	if false {

		certManagerID := gk8s.Release(clusterID, &certManager)

		certsID := gk8s.Manifests(clusterID, &certs, certManagerID)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx, certsID)

		waitForIngressWebhookID := gk8s.ClusterAction(
			clusterID,
			"Wait for Ingress Webhook",
			gingk8s.ClusterAction(waitForIngressWebhook),
			ingressNginxID,
		)

		kubeIngressProxyID := gk8s.Release(clusterID, &kubeIngressProxy, ingressNginxID)

		postgresOperatorID := gk8s.Release(clusterID, &postgresOperator, certsID)

		postgresID := gk8s.Manifests(clusterID, &postgres, postgresOperatorID)

		postgresSecretsReadyID := gk8s.ClusterAction(clusterID, "Wait for Postgres Secrets", postgresSecretsReady, nil)

		minioID := gk8s.Release(clusterID, &minio)

		mlflowIDs := []gingk8s.ReleaseID{
			gk8s.Release(clusterID, &mlflow[0],
				minioID,
				postgresID,
				postgresSecretsReadyID,
			),
			gk8s.Release(clusterID, &mlflow[1], minioID,
				postgresID,
				postgresSecretsReadyID,
			),
		}

		keycloakID := gk8s.Release(clusterID, &keycloak, postgresID, waitForIngressWebhookID)

		keycloakSetupID := gk8s.ClusterAction(
			clusterID,
			"Create Keycloak Realm, Users, and Clients",
			gingk8s.ClusterAction(keycloakSetup(
				"keycloak-0",
				"REALM=integration-test",
				"KEYCLOAK_URL=https://keycloak.default.svc.cluster.local",
			)),
			keycloakID,
		)

		mlflowOIDCProxySetupID := gk8s.ClusterAction(clusterID,
			"Generate MLFlow OIDC Proxy ConfigMap",
			gingk8s.ClusterAction(mlflowOIDCProxySetup),
		)

		mlflowOIDCProxyConfigID := gk8s.Manifests(clusterID, &mlflowOIDCProxyConfig, mlflowOIDCProxySetupID)

		mlflowOIDCProxyID := gk8s.Release(clusterID, &mlflowOIDCProxy,
			mlflowOIDCProxySetupID,
			mlflowOIDCProxyConfigID,
			mlflowOIDCProxyImageID,
		)

		oauth2ProxySetupID := gk8s.ClusterAction(clusterID, "Generate OAuth2 Proxy ConfigMap", gingk8s.ClusterAction(oauth2ProxySetup))

		oauth2ProxyConfigID := gk8s.Manifests(clusterID, &oauth2ProxyConfig,
			oauth2ProxySetupID,
			ingressNginxID,
		)

		oauth2ProxyID := gk8s.Release(clusterID, &oauth2Proxy,
			keycloakID,
			oauth2ProxyConfigID,
			oauth2ProxyImageID,
			keycloakSetupID, waitForIngressWebhookID,
		)

		jupyterhubID := gk8s.Release(clusterID, &jupyterhub,
			keycloakID,
			jupyterhubImageID,
			keycloakSetupID, waitForIngressWebhookID, postgresSecretsReadyID,
		)

		_ = gingk8s.ResourceDependencies{
			Releases: []gingk8s.ReleaseID{
				kubeIngressProxyID,
				jupyterhubID,
				oauth2ProxyID,
				mlflowOIDCProxyID,
				mlflowIDs[0],
				mlflowIDs[1],
			},
		}

	} else {
		mlflowDepsID := gk8s.Release(clusterID, &mlflowMultitenantDeps)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx2) //	certsID,

		waitForIngressWebhookID := gk8s.ClusterAction(clusterID, "Wait for Ingress Webhook", gingk8s.ClusterAction(waitForIngressWebhook), ingressNginxID)

		kubeIngressProxyID := gk8s.Release(clusterID, &kubeIngressProxy, ingressNginxID)

		mlflowID := gk8s.Release(clusterID, &mlflowMultitenant,
			mlflowDepsID,
			oauth2ProxyImageID,
			mlflowOIDCProxyImageID,
			waitForIngressWebhookID,
		)

		certsID := gk8s.Manifests(clusterID, &certsNoIssuer, mlflowDepsID, mlflowID)

		postgresSecretsReadyID := gk8s.ClusterAction(clusterID, "Wait for Postgres Secrets", multitenantPostgresSecretsReady, mlflowID)

		jupyterhubID := gk8s.Release(clusterID, &jupyterhub2,
			mlflowID,
			jupyterhubImageID,
			waitForIngressWebhookID, postgresSecretsReadyID,
		)

		keycloakSetupID := gk8s.ClusterAction(
			clusterID,
			"Create Keycloak Realm, Users, and Clients",
			gingk8s.ClusterAction(keycloakSetup(
				"mlflow-multitenant-keycloak-0",
				"REALM=mlflow-multitenant",
				"USERS_ONLY=1",
				"KEYCLOAK_URL=https://mlflow-multitenant-keycloak.default.svc.cluster.local",
			)),
			mlflowID,
		)

		_ = gingk8s.ResourceDependencies{
			Releases: []gingk8s.ReleaseID{
				kubeIngressProxyID,
				jupyterhubID,
				mlflowID,
			},
			Manifests: []gingk8s.ManifestsID{
				certsID,
			},
			ClusterActions: []gingk8s.ClusterActionID{
				keycloakSetupID,
			},
		}
	}

	gk8s.Options(gingk8s.SuiteOpts{
		NoSuiteCleanup: true,
	})
	gk8s.Setup(ctx)

	biloba.SpinUpChrome(GinkgoT(),
		chromedp.ProxyServer("http://localhost:8080"),
		chromedp.Flag("headless", false),
		chromedp.Flag("ignore-certificate-errors", "1"),
	)
	b = biloba.ConnectToChrome(GinkgoT())
	keycloakLogin(true)
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
			"hostPort.enabled":                 true,
		},
	}

	postgresOperator = gingk8s.HelmRelease{
		Name: "postgres-operator",
		Chart: &gingk8s.HelmChart{
			RemoteChartInfo: gingk8s.RemoteChartInfo{
				Name: "postgres-operator",
				Repo: &gingk8s.HelmRepo{
					Name: "zalando",
					URL:  "https://opensource.zalando.com/postgres-operator/charts/postgres-operator",
				},
				Version: "1.9.0",
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
		},

		gingk8s.HelmRelease{
			Name: "mlflow-tenant-2",
			Chart: &gingk8s.HelmChart{
				LocalChartInfo: gingk8s.LocalChartInfo{
					Path: "integration-test/mlflow",
				},
			},
			Set: mlflowSet(2),
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
			"image.tag":                     gingk8s.DefaultExtraCustomImageTags()[0],
			// "image.tag":                     gingk8s.DefaultCustomImageTag,
		},
	}

	oauth2ProxyConfigMapPath = "integration-test/oauth2-proxy-cfg-configmap.yaml"

	oauth2ProxyConfig = gingk8s.KubernetesManifests{
		Name:          "OAuth2 Proxy Config",
		ResourcePaths: []string{oauth2ProxyConfigMapPath},
	}

	oauth2ProxyImage = gingk8s.ThirdPartyImage{
		Name:   "local.host/mlflow-oidc-proxy/oauth2-proxy:latest",
		NoPull: true,
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
			"image.tag":                         "latest",
			"image.pullPolicy":                  "Never",
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
				Path: "deploy/helm/mlflow-multitenant-deps",
			},
		},
	}

	mlflowMultitenant = gingk8s.HelmRelease{
		Name: "mlflow-multitenant",
		Chart: &gingk8s.HelmChart{
			LocalChartInfo: gingk8s.LocalChartInfo{
				Path: "deploy/helm/mlflow-multitenant",
			},
		},
		ValuesFiles:  []string{"deploy/helm/mlflow-multitenant/values.yaml"},
		UpgradeFlags: []string{"--wait-for-jobs"},
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
			"oauth2-proxy.image.tag":                      "latest",
			"oauth2-proxy.image.pullPolicy":               "Never",
			"oauth2-proxy.hostAliases[0].ip":              getIngressControllerIP,
			"oauth2-proxy.hostAliases[0].hostnames[0]":    "keycloak.mlflow-oidc-proxy-it.cluster",

			"mlflow-oidc-proxy.image.pullPolicy": "Never",
			"mlflow-oidc-proxy.image.repository": mlflowOIDCProxyImage.WithTag(""),
			"mlflow-oidc-proxy.image.tag":        gingk8s.DefaultExtraCustomImageTags()[0],
			//"mlflow-oidc-proxy.image.tag":        gingk8s.DefaultCustomImageTag,

			"keycloakJob.extraClients[0].id":          "jupyterhub",
			"keycloakJob.extraClients[0].secretName":  "mlflow-multitenant-jupyterhub-oidc",
			"keycloakJob.extraClients[0].callbackURL": "https://jupyterhub.mlflow-oidc-proxy-it.cluster/hub/oauth_callback",

			"postgres.extraUsers.jupyterhub":     "null",
			"postgres.extraDatabases.jupyterhub": "jupyterhub",

			"mlflow.tenants[0].id":   "tenant-1",
			"mlflow.tenants[0].name": "Tenant 1",
			"mlflow.tenants[1].id":   "tenant-2",
			"mlflow.tenants[1].name": "Tenant 2",
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

	fCfg, err := os.Open("integration-test/oauth2_proxy.cfg")
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

	fCfg, err := os.Open("integration-test/mlflow-oidc-proxy.cfg")
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
