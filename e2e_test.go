package main_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unicode"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
	"github.com/meln5674/gingk8s"
	"github.com/onsi/biloba"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	RunningInContainerEnv = "RUNNING_IN_CONTAINER"
)

var (
	runningInContainer = os.Getenv(RunningInContainerEnv) != ""
)

type PredictionOutput struct {
	Predictions []float64
}

type subSuite struct {
	b *biloba.Biloba
	g gingk8s.Gingk8s
}

func (s *subSuite) nodes(sel interface{}) []*cdp.Node {
	GinkgoHelper()
	b := s.b
	var toReturn []*cdp.Node
	Expect(chromedp.Run(b.Context, chromedp.QueryAfter(sel, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
		toReturn = nodes
		return nil
	}))).To(Succeed())
	return toReturn
}

func (s *subSuite) mouseClick(sel interface{}, opts ...chromedp.MouseOption) {
	GinkgoHelper()
	b := s.b
	Expect(chromedp.Run(b.Context, chromedp.QueryAfter(sel, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
		Expect(nodes).To(HaveLen(1))
		return chromedp.MouseClickNode(nodes[0], opts...).Do(ctx)
	}))).To(Succeed())
}

func (s *subSuite) mouseMove(sel interface{}, opts ...chromedp.MouseOption) {
	GinkgoHelper()
	b := s.b
	Expect(chromedp.Run(b.Context, chromedp.QueryAfter(sel, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
		Expect(nodes).To(HaveLen(1))
		return MouseMoveNode(nodes[0], opts...).Do(ctx)
	}))).To(Succeed())
}

// MouseClickXY is an action that sends a left mouse button click (i.e.,
// mousePressed and mouseReleased event) to the X, Y location.
func MouseMoveXY(x, y float64, opts ...chromedp.MouseOption) chromedp.MouseAction {
	GinkgoHelper()
	return chromedp.ActionFunc(func(ctx context.Context) error {
		p := &input.DispatchMouseEventParams{
			Type: input.MouseMoved,
			X:    x,
			Y:    y,
		}

		// apply opts
		for _, o := range opts {
			p = o(p)
		}

		return p.Do(ctx)
	})
}

// MouseClickNode is an action that dispatches a mouse left button click event
// at the center of a specified node.
//
// Note that the window will be scrolled if the node is not within the window's
// viewport.
func MouseMoveNode(n *cdp.Node, opts ...chromedp.MouseOption) chromedp.MouseAction {
	GinkgoHelper()
	return chromedp.ActionFunc(func(ctx context.Context) error {
		t := cdp.ExecutorFromContext(ctx).(*chromedp.Target)
		if t == nil {
			return chromedp.ErrInvalidTarget
		}

		if err := dom.ScrollIntoViewIfNeeded().WithNodeID(n.NodeID).Do(ctx); err != nil {
			return err
		}

		boxes, err := dom.GetContentQuads().WithNodeID(n.NodeID).Do(ctx)
		if err != nil {
			return err
		}

		if len(boxes) == 0 {
			return chromedp.ErrInvalidDimensions
		}

		content := boxes[0]

		c := len(content)
		if c%2 != 0 || c < 1 {
			return chromedp.ErrInvalidDimensions
		}

		var x, y float64
		for i := 0; i < c; i += 2 {
			x += content[i]
			y += content[i+1]
		}
		x /= float64(c / 2)
		y /= float64(c / 2)

		return MouseMoveXY(x, y, opts...).Do(ctx)
	})
}

func EncodeNoChar(r rune) []*input.DispatchKeyEventParams {
	GinkgoHelper()
	// force \n -> \r
	if r == '\n' {
		r = '\r'
	}
	// if not known key, encode as unidentified
	v, ok := kb.Keys[r]
	Expect(ok).To(BeTrue(), fmt.Sprintf("Unidentified key rune: %v", r))
	// create
	keyDown := input.DispatchKeyEventParams{
		Key:                   v.Key,
		Code:                  v.Code,
		Text:                  string(r),
		UnmodifiedText:        string(unicode.ToLower(r)),
		NativeVirtualKeyCode:  v.Native,
		WindowsVirtualKeyCode: v.Windows,
	}
	if runtime.GOOS == "darwin" {
		keyDown.NativeVirtualKeyCode = 0
	}
	if v.Shift {
		keyDown.Modifiers |= input.ModifierShift
	}
	keyUp := keyDown
	keyDown.Type, keyUp.Type = input.KeyDown, input.KeyUp
	return []*input.DispatchKeyEventParams{&keyDown, &keyUp}
}

func KeyEventNoChar(keys string, opts ...chromedp.KeyOption) chromedp.KeyAction {
	GinkgoHelper()
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for _, r := range keys {
			for _, k := range EncodeNoChar(r) {
				for _, o := range opts {
					o(k)
				}
				if err := k.Do(ctx); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (s *subSuite) keycloakToken(ctx context.Context, needCredentials bool) string {
	GinkgoHelper()
	b := s.b
	By("Navigating to the oauth proxy sign-in")
	mlflowURL := fmt.Sprintf("https://%s/oauth2/sign_in", oauth2Proxy.Set["ingress.hostname"])

	waitFor200(ctx, s.g, mlflowURL)

	b.Navigate(mlflowURL)
	generateTokenXPath := "/html/body/section/div/form[2]/button"
	Eventually(b.XPath(generateTokenXPath), "30s").Should(b.Exist())

	By("Entering keycloak credentials for a token")
	b.Click(b.XPath(generateTokenXPath))
	if needCredentials {
		Eventually(b.Location, "5s").Should(HavePrefix(fmt.Sprintf("https://%s/", keycloak.Set["ingress.hostname"])))
		b.SetValue("#username", "tenant-1")
		b.SetValue("#password", "test")
		b.Click("#kc-login")
	}
	Eventually(b.Location, "5s").Should(HavePrefix(fmt.Sprintf("https://%s/oauth2/callback", oauth2Proxy.Set["ingress.hostname"])))
	Eventually("#token-box").Should(b.Exist())
	return b.GetValue("#token-box").(string)
}

func (s *subSuite) keycloakLogin(ctx context.Context, needCredentials bool) {
	GinkgoHelper()
	b := s.b
	By("Navigating to the oauth proxy sign-in")
	mlflowURL := fmt.Sprintf("https://%s/oauth2/sign_in", oauth2Proxy.Set["ingress.hostname"])

	waitFor200(ctx, s.g, mlflowURL)

	b.Navigate(mlflowURL)
	loginButton := b.XPath("/html/body/section/div/form[1]/button")
	Eventually(loginButton, "30s").Should(b.Exist())

	By("Entering keycloak credentials for typical login")
	b.Click(loginButton)
	if needCredentials {
		Eventually(b.Location, "30s").Should(HavePrefix(fmt.Sprintf("https://%s/", keycloak.Set["ingress.hostname"])))
		b.SetValue("#username", "tenant-1")
		b.SetValue("#password", "test")
		b.Click("#kc-login")
	}

	Eventually(b.Location, "30s").Should(Equal(fmt.Sprintf("https://%s/", oauth2Proxy.Set["ingress.hostname"])))
}

func (s *subSuite) sessionSetup(ctx context.Context, g gingk8s.Gingk8s) {
	proxy, err := getProxyURL(g, ctx, &cluster)
	Expect(err).ToNot(HaveOccurred())
	bopts := []chromedp.ExecAllocatorOption{
		chromedp.ProxyServer(proxy),
		//chromedp.Flag("headless", false),
		chromedp.Flag("ignore-certificate-errors", "1"),
	}
	if runningInContainer {
		bopts = append(bopts, chromedp.NoSandbox)
		GinkgoWriter.Printf("!!! WARNING: Sandbox disabled due to containerized environment detected from %s. This is insecure if this not actually a container!\n", RunningInContainerEnv)
	}

	biloba.SpinUpChrome(GinkgoT(), bopts...)
	s.b = biloba.ConnectToChrome(GinkgoT())
	s.keycloakLogin(ctx, true)
}

// func (s *subSuite) loginAndRunNotebook(extraVars string, expectedSubject string) {
func (s *subSuite) loginAndRunNotebook(ctx context.Context, uri, token, certAndKey, expectedSubject string) {

	b := s.b

	By("Executing the test notebook in a job")

	outputDir, err := os.MkdirTemp("integration-test", "notebook-output-*")
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() { os.RemoveAll(outputDir) })

	outputMount := filepath.Join("/mnt/host/mlflow-oidc-proxy/integration-test", filepath.Base(outputDir))

	gk8s := s.g.ForSpec()

	gk8s.Release(clusterID, notebookJob(uri, token, certAndKey, "test-cert", outputMount))
	gk8s.ClusterAction(clusterID, "Notebook Job Logs", &gingk8s.KubectlLogger{
		Kind:          "job",
		Name:          "run-notebook",
		RetryPeriod:   2 * time.Second,
		StopOnSuccess: true,
	})

	gk8s.Setup(ctx)

	By("Parsing the final cell's output as JSON")

	var output PredictionOutput
	/*
		Expect(json.Unmarshal([]byte(b.InnerText(codeCellTextOutputFmt(57))), &output)).To(Succeed())
		Expect(output.Predictions).To(HaveLen(1))
	*/

	f, err := os.Open(filepath.Join(outputDir, "MLflow-example-notebook.ipynb"))
	Expect(err).ToNot(HaveOccurred())

	var notebook map[string]interface{}
	Expect(json.NewDecoder(f).Decode(&notebook)).To(Succeed())

	Expect(notebook).To(HaveKey("cells"))
	cells := notebook["cells"].([]interface{})

	Expect(cells).To(HaveLen(58))
	finalCell := cells[56].(map[string]interface{})

	Expect(finalCell).To(HaveKeyWithValue("outputs", HaveLen(1)))
	finalCellOutput := finalCell["outputs"].([]interface{})[0].(map[string]interface{})
	Expect(finalCellOutput).To(HaveKey("text"))

	finalCellOutputText := finalCellOutput["text"].([]interface{})[0].(string)

	Expect(json.Unmarshal([]byte(finalCellOutputText), &output)).To(Succeed())
	Expect(output.Predictions).To(HaveLen(1))

	By("Navigating to the MLFlow tenant")

	mlflowURL := fmt.Sprintf("https://%s/", oauth2Proxy.Set["ingress.hostname"])
	b.Navigate(mlflowURL)
	mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-1", oauth2Proxy.Set["ingress.hostname"])

	tenantButton := fmt.Sprintf(`a[href="%s/"]`, mlflowTenantURL)
	Eventually(tenantButton, "30s").Should(b.Exist())
	b.Click(tenantButton)
	Eventually(b.Location, "5s").Should(HavePrefix(fmt.Sprintf("%s/#/experiments/", mlflowTenantURL)))
	experimentButton := `a[href="#/experiments/1`
	Eventually(experimentButton, "30s").Should(b.Exist())
	b.Click(experimentButton)
	Eventually(b.Location, "30s").Should(HavePrefix(fmt.Sprintf("%s/#/experiments/1", mlflowTenantURL)))

	mostRecentRun := `div.ag-pinned-left-cols-container > .ag-row-even:nth-child(1) a`
	Eventually(mostRecentRun, "30s").Should(b.Exist())
	b.Click(mostRecentRun)

	userField := `#root > div > div > div > table > tbody > tr:nth-child(2) > td > a`
	Eventually(userField, "1m").Should(b.Exist())
	Expect(userField).To(b.HaveInnerText(expectedSubject))
}

func (s *subSuite) cases(robotCertSecretName string, robotTokenSecretName, caSecretName string) {
	var _ = BeforeEach(func(ctx context.Context) {
		s.sessionSetup(ctx, s.g)
		s.b.Prepare()

	})
	Describe("Tenant 1", func() {
		It("should execute an mlflow jupyterlab notebook with a generated token", func(ctx context.Context) {
			apiToken := s.keycloakToken(ctx, false)
			s.keycloakLogin(ctx, false)

			// s.loginAndRunNotebook(fmt.Sprintf(`MLFLOW_TRACKING_TOKEN='%s' MLFLOW_TRACKING_URI='%s' `, apiToken, "https://mlflow.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/"), "tenant-1")
			s.loginAndRunNotebook(ctx, "https://mlflow.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/", apiToken, "", "tenant-1")
		})

		It("should execute an mlflow jupyterlab notebook with a robot certificate", func(ctx context.Context) {
			robotKey := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotCertSecretName, "tls.key")
			robotCert := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotCertSecretName, "tls.crt")
			s.keycloakLogin(ctx, false)

			// s.loginAndRunNotebook(fmt.Sprintf(`MLFLOW_TRACKING_CLIENT_CERT_AND_KEY='%s' MLFLOW_TRACKING_URI='%s'`, robotKey+"\n"+robotCert, "https://mlflow-api.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/"), "robot-1")
			s.loginAndRunNotebook(ctx, "https://mlflow-api.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/", "", robotKey+"\n"+robotCert, "robot-1")
		})

		It("should execute an mlflow jupyterlab notebook with a robot token", func(ctx context.Context) {
			robotToken := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotTokenSecretName, "token")
			s.keycloakLogin(ctx, false)

			// s.loginAndRunNotebook(fmt.Sprintf(`MLFLOW_TRACKING_TOKEN='%s' MLFLOW_TRACKING_URI='%s'`, robotToken, "https://mlflow-api.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/"), "robot-3")
			s.loginAndRunNotebook(ctx, "https://mlflow-api.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/", robotToken, "", "robot-3")
		})
	})

	Describe("Tenant-2", func() {
		It("Should not have access to the other MLFLow tenant using a generated token", func() {
			b := s.b
			mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-2/", oauth2Proxy.Set["ingress.hostname"])
			b.NavigateWithStatus(mlflowTenantURL, http.StatusForbidden)

		})
		It("Should not have access to the other MLFLow tenant using a robot certificate", func(ctx context.Context) {
			robotKey := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotCertSecretName, "tls.key")
			robotCert := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotCertSecretName, "tls.crt")
			robotCA := gk8s.KubectlReturnSecretValue(ctx, &cluster, caSecretName, "ca.crt")

			keypair, err := tls.X509KeyPair([]byte(robotCert), []byte(robotKey))
			Expect(err).ToNot(HaveOccurred())
			pool := x509.NewCertPool()
			Expect(pool.AppendCertsFromPEM([]byte(robotCA))).To(BeTrue())

			mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-2/", oauth2Proxy.Set["ingress.hostname"])
			proxy, err := getProxyURL(gk8s, ctx, &cluster)
			Expect(err).ToNot(HaveOccurred())
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:      pool,
						Certificates: []tls.Certificate{keypair},
					},
					Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(proxy) },
				},
			}
			resp, err := client.Get(mlflowTenantURL)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusForbidden))

		})

		It("Should not have access to the other MLFLow tenant using a robot token", func(ctx context.Context) {
			robotToken := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotTokenSecretName, "token")
			robotCA := gk8s.KubectlReturnSecretValue(ctx, &cluster, caSecretName, "ca.crt")

			pool := x509.NewCertPool()
			Expect(pool.AppendCertsFromPEM([]byte(robotCA))).To(BeTrue())

			mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-2/", oauth2Proxy.Set["ingress.hostname"])
			proxy, err := getProxyURL(gk8s, ctx, &cluster)
			Expect(err).ToNot(HaveOccurred())
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: pool,
					},
					Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(proxy) },
				},
			}
			req, err := http.NewRequest(http.MethodGet, mlflowTenantURL, nil)
			Expect(err).ToNot(HaveOccurred())
			req.Header.Set("Authorization", "Bearer "+robotToken)
			resp, err := client.Do(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
		})
	})
}

var _ = Describe("Standalone setup", Ordered, func() {
	s := subSuite{}
	BeforeAll(func() {
		gspec := gk8s.ForSpec()
		gk8s := gspec
		s.g = gk8s

		gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)
		gk8s.ClusterAction(clusterID, "Watch Events", watchEvents)

		certManagerID := gk8s.Release(clusterID, &certManager)

		certsID := gk8s.Manifests(clusterID, &certs, certManagerID)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx, certsID)

		gk8s.ClusterAction(
			clusterID,
			"Restart kube ingress proxy",
			restartKubeIngressProxy,
			ingressNginxID,
		)

		waitForIngressWebhookID := gk8s.ClusterAction(
			clusterID,
			"Wait for Ingress Webhook",
			gingk8s.ClusterAction(waitForIngressWebhook),
			ingressNginxID,
		)

		postgresOperatorID := gk8s.Release(clusterID, &postgresOperator, certsID)

		waitForPostgresDeletionID := gk8s.ClusterAction(clusterID, "Wait for postgres to be cleaned up before deleting operator", waitForPostgresDeletion, postgresOperatorID)

		postgresID := gk8s.Manifests(clusterID, &postgres, postgresOperatorID, waitForPostgresDeletionID)

		postgresSecretsReadyID := gk8s.ClusterAction(clusterID, "Wait for Postgres Secrets", postgresSecretsReady, postgresID)

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
			certsID,
		)

		oauth2ProxySetupID := gk8s.ClusterAction(clusterID, "Generate OAuth2 Proxy ConfigMap", gingk8s.ClusterAction(oauth2ProxySetup))

		oauth2ProxyConfigID := gk8s.Manifests(clusterID, &oauth2ProxyConfig,
			oauth2ProxySetupID,
			ingressNginxID,
		)

		oauth2ProxyID := gk8s.Release(clusterID, &oauth2Proxy,
			keycloakID,
			oauth2ProxyConfigID,
			keycloakSetupID, waitForIngressWebhookID,
		)

		/*jupyterhubID := gk8s.Release(clusterID, &jupyterhub,
			keycloakID,
			keycloakSetupID, waitForIngressWebhookID, postgresSecretsReadyID,
		)*/

		/*terminals := */
		_ = gingk8s.ResourceDependencies{
			Releases: append(
				[]gingk8s.ReleaseID{
					// jupyterhubID,
					mlflowOIDCProxyID,
					oauth2ProxyID,
				},
				mlflowIDs...,
			),
		}

		// gk8s.ClusterAction(clusterID, "Describe Pods on Failure", gingk8s.ClusterCleanupAction(DescribePods), &terminals)
		gk8s.ClusterAction(clusterID, "Ingress Logs", &gingk8s.KubectlLogger{
			Kind:        "ds",
			Name:        "ingress-nginx-controller",
			RetryPeriod: 15 * time.Second,
		}, ingressNginxID)
		gk8s.ClusterAction(clusterID, "Oauth2 Proxy Logs", &gingk8s.KubectlLogger{
			Kind:        "deploy",
			Name:        "oauth2-proxy",
			RetryPeriod: 15 * time.Second,
		}, oauth2ProxyID)
		gk8s.ClusterAction(clusterID, "MLFLow Tenant 1 Logs", &gingk8s.KubectlLogger{
			Kind:        "deploy",
			Name:        "mlflow-tenant-1",
			RetryPeriod: 15 * time.Second,
		}, mlflowIDs[0])

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		gk8s.Setup(ctx)
	})
	s.cases("robot-1", "robot-3", "test-cert")
})

var _ = Describe("Omnibus setup", Ordered, func() {
	s := subSuite{}
	BeforeAll(func() {
		gspec := gk8s.ForSpec()
		gk8s := gspec
		s.g = gk8s

		gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)
		gk8s.ClusterAction(clusterID, "Watch Events", watchEvents)

		mlflowDepsID := gk8s.Release(clusterID, &mlflowMultitenantDeps)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx2)

		gk8s.ClusterAction(
			clusterID,
			"Restart kube ingress proxy",
			restartKubeIngressProxy,
			ingressNginxID,
		)

		gk8s.ClusterAction(clusterID, "Wait for postgres to be cleaned up before deleting operator", waitForPostgresDeletion, mlflowDepsID)

		gk8s.ClusterAction(clusterID, "Ingress Logs", &gingk8s.KubectlLogger{
			Kind:        "ds",
			Name:        "ingress-nginx-controller",
			RetryPeriod: 15 * time.Second,
		}, ingressNginxID)

		// gk8s.ClusterAction(clusterID, "Describe Pods on Failure", gingk8s.ClusterCleanupAction(DescribePods), &terminals)

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		gk8s.Setup(ctx)
	})

	When("using object store", func() {
		BeforeAll(func() {
			gk8s := s.g.ForSpec()
			mlflowID := gk8s.Release(clusterID, &mlflowMultitenantObjectStore)
			gk8s.ClusterAction(
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
			gk8s.ClusterAction(clusterID, "Oauth2 Proxy Logs", &gingk8s.KubectlLogger{
				Kind:        "deploy",
				Name:        "mlflow-multitenant-oauth2-proxy",
				RetryPeriod: 15 * time.Second,
			}, mlflowID)
			gk8s.ClusterAction(clusterID, "Clean up keycloak secret on finish", gingk8s.ClusterCleanupAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
				return g.Kubectl(ctx, cluster, "delete", "secret", "mlflow-multitenant-oidc", "--ignore-not-found").Run()
			}), mlflowID)
			gk8s.Manifests(clusterID, &certsNoIssuer, mlflowID)

			// postgresSecretsReadyID :=
			gk8s.ClusterAction(clusterID, "Wait for Postgres Secrets", multitenantPostgresSecretsReady, mlflowID)

			/*gk8s.Release(clusterID, &jupyterhub2,
				mlflowID,
				postgresSecretsReadyID,
			)*/
			ctx, cancel := context.WithCancel(context.Background())
			DeferCleanup(cancel)
			gk8s.Setup(ctx)
		})
		s.cases("mlflow-multitenant-robot-robot-1", "mlflow-multitenant-robot-robot-3", "mlflow-multitenant-robot-robot-1")
	})

	When("using pvc store", func() {
		BeforeAll(func() {
			gk8s := s.g.ForSpec()
			mlflowID := gk8s.Release(clusterID, &mlflowMultitenantPVCStore)
			gk8s.ClusterAction(
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
			gk8s.ClusterAction(clusterID, "Oauth2 Proxy Logs", &gingk8s.KubectlLogger{
				Kind:        "deploy",
				Name:        "mlflow-multitenant-oauth2-proxy",
				RetryPeriod: 15 * time.Second,
			}, mlflowID)
			gk8s.ClusterAction(clusterID, "Clean up keycloak secret on finish", gingk8s.ClusterCleanupAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
				return g.Kubectl(ctx, cluster, "delete", "secret", "mlflow-multitenant-oidc", "--ignore-not-found").Run()
			}), mlflowID)

			gk8s.Manifests(clusterID, &certsNoIssuer, mlflowID)

			// postgresSecretsReadyID :=
			gk8s.ClusterAction(clusterID, "Wait for Postgres Secrets", multitenantPostgresSecretsReady, mlflowID)

			/*gk8s.Release(clusterID, &jupyterhub2,
				mlflowID,
				postgresSecretsReadyID,
			)*/
			ctx, cancel := context.WithCancel(context.Background())
			DeferCleanup(cancel)
			gk8s.Setup(ctx)
		})
		s.cases("mlflow-multitenant-robot-robot-1", "mlflow-multitenant-robot-robot-3", "mlflow-multitenant-robot-robot-1")
	})

})

var _ = Describe("Omnibus setup in Default Configuration", Ordered, func() {
	s := subSuite{}
	BeforeAll(func() {
		gspec := gk8s.ForSpec()
		gk8s := gspec
		s.g = gk8s

		gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)
		gk8s.ClusterAction(clusterID, "Watch Events", watchEvents)
		// gk8s.ClusterAction(clusterID, "Describe Pods on Failure", gingk8s.ClusterCleanupAction(DescribePods))

		mlflowDepsID := gk8s.Release(clusterID, &mlflowMultitenantDeps)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx2)

		waitForIngressWebhookID := gk8s.ClusterAction(clusterID, "Wait for Ingress Webhook", gingk8s.ClusterAction(waitForIngressWebhook), ingressNginxID)

		// gk8s.ClusterAction(clusterID, "Keycloak 0 Logs", &gingk8s.KubectlLogger{Kind: "pod", Name: "mlflow-multitenant-keycloak-0", RetryPeriod: 15 * time.Second})
		gk8s.ClusterAction(clusterID, "Keycloak Configuration Job Logs", &gingk8s.KubectlLogger{
			Kind:          "job",
			Name:          "mlflow-multitenant-configure-keycloak-1",
			RetryPeriod:   15 * time.Second,
			Flags:         []string{"-c", "config"},
			StopOnSuccess: true,
		})
		gk8s.ClusterAction(clusterID, "Minio Configuration Job Logs", &gingk8s.KubectlLogger{
			Kind:          "job",
			Name:          "mlflow-multitenant-configure-minio-1",
			RetryPeriod:   15 * time.Second,
			Flags:         []string{"-c", "config"},
			StopOnSuccess: true,
		})

		waitForPostgresDeletionID := gk8s.ClusterAction(clusterID, "Wait for postgres to be cleaned up before deleting operator", waitForPostgresDeletion, mlflowDepsID)

		mlflowID := gk8s.Release(clusterID, &mlflowMultitenantDefaults,
			mlflowDepsID,
			waitForIngressWebhookID,
			waitForPostgresDeletionID,
		)

		gk8s.ClusterAction(clusterID, "Clean up keycloak secret on finish", gingk8s.ClusterCleanupAction(func(g gingk8s.Gingk8s, ctx context.Context, cluster gingk8s.Cluster) error {
			return g.Kubectl(ctx, cluster, "delete", "secret", "mlflow-multitenant-oidc", "--ignore-not-found").Run()
		}), mlflowID)

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		gk8s.Setup(ctx)
	})

	It("Should start", func() {
		// This test deliberately left blank

		// We are just testing that running "helm install" without any additional changes actually starts into a valid state where all of the pods are running
	})
})

func waitFor200(ctx context.Context, gk8s gingk8s.Gingk8s, urlString string) {
	proxy, err := getProxyURL(gk8s, ctx, &cluster)
	Expect(err).ToNot(HaveOccurred())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(proxy) },
		},
	}
	Eventually(func() error {
		_, err := client.Get(urlString)
		return err
	}, "5s").Should(Succeed())
	Eventually(func(g Gomega) int {
		resp, err := client.Get(urlString)
		g.Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, err = io.Copy(&buf, resp.Body)
		g.Expect(err).ToNot(HaveOccurred())
		if resp.StatusCode != http.StatusOK {
			GinkgoLogr.Info("wait-for-200 response", "url", urlString, "body", buf.String())
		}
		return resp.StatusCode
	}, "5s").Should(Equal(http.StatusOK))
}
