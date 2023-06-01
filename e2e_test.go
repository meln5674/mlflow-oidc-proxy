package main_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

type PredictionOutput struct {
	Predictions []float64
}

type subSuite struct {
	b *biloba.Biloba
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

func (s *subSuite) keycloakToken(needCredentials bool) string {
	GinkgoHelper()
	b := s.b
	By("Navigating to the oauth proxy sign-in")
	mlflowURL := fmt.Sprintf("https://%s/oauth2/sign_in", oauth2Proxy.Set["ingress.hostname"])
	b.Navigate(mlflowURL)
	generateTokenXPath := "/html/body/section/div/form[2]/button"
	Eventually(b.XPath(generateTokenXPath)).Should(b.Exist())

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

func (s *subSuite) keycloakLogin(needCredentials bool) {
	GinkgoHelper()
	b := s.b
	By("Navigating to the oauth proxy sign-in")
	mlflowURL := fmt.Sprintf("https://%s/oauth2/sign_in", oauth2Proxy.Set["ingress.hostname"])
	b.Navigate(mlflowURL)
	loginButton := b.XPath("/html/body/section/div/form[1]/button")
	Eventually(loginButton).Should(b.Exist())

	By("Entering keycloak credentials for typical login")
	b.Click(loginButton)
	if needCredentials {
		Eventually(b.Location, "5s").Should(HavePrefix(fmt.Sprintf("https://%s/", keycloak.Set["ingress.hostname"])))
		b.SetValue("#username", "tenant-1")
		b.SetValue("#password", "test")
		b.Click("#kc-login")
	}

	Eventually(b.Location, "5s").Should(Equal(fmt.Sprintf("https://%s/", oauth2Proxy.Set["ingress.hostname"])))
}

func (s *subSuite) sessionSetup() {
	biloba.SpinUpChrome(GinkgoT(),
		chromedp.ProxyServer("http://localhost:8080"),
		//chromedp.Flag("headless", false),
		chromedp.Flag("ignore-certificate-errors", "1"),
	)
	s.b = biloba.ConnectToChrome(GinkgoT())
	s.keycloakLogin(true)
}

func (s *subSuite) loginAndRunNotebook(extraVars string, expectedSubject string) {
	b := s.b
	By("Going to Jupyterhub")
	b.Navigate(fmt.Sprintf("https://%s/", jupyterhub.Set["ingress.hosts[0]"]))
	Eventually(".btn.btn-jupyter.btn-lg").Should(b.Exist())
	b.Click(".btn.btn-jupyter.btn-lg")

	By("Navigating to the workspace root")
	// The file browser loads so slowly, that by the time we've opened a terminal on a pre-warmed instance, it re-navigates to the cached location after we've already clicked the root button
	// There doesn't seem to be any obvious element whose existence indicates the browser is actually finished loading
	time.Sleep(15 * time.Second)
	rootFolderButton := ".jp-BreadCrumbs-home"
	// This has a very long timeout because on github actions, the server pod takes a long time to provision
	Eventually(rootFolderButton, "5m").Should(b.Exist())
	// When running headless, for whatever reason,
	// the button doesn't immediately generate a layout, which causes the scrollIntoView to fail
	time.Sleep(15 * time.Second)
	s.mouseClick(rootFolderButton, chromedp.ButtonLeft)
	folder := `.jp-BreadCrumbs [title="mlflow-example"]`
	Eventually(folder).ShouldNot(b.Exist())

	By("Opening a new launcher")
	fileButton := `div[role="banner"] .lm-MenuBar-content > li:nth-child(1)`
	Eventually(fileButton).Should(b.Exist())
	s.mouseClick(fileButton, chromedp.ButtonLeft)
	time.Sleep(1 * time.Second)
	launcherButton := `div.lm-Widget.p-Widget.lm-Menu.p-Menu [data-command="filebrowser:create-main-launcher"]`
	Eventually(launcherButton).Should(b.Exist())
	s.mouseMove(launcherButton)
	// Expect(chromedp.Run(b.Context, chromedp.QueryAfter(launcherButton, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
	// 	Expect(nodes).To(HaveLen(1))
	// 	return MouseMoveNode(nodes[0]).Do(ctx)
	// }))).To(Succeed())
	//time.Sleep(5 * time.Second)
	s.mouseClick(launcherButton, chromedp.ButtonLeft)

	// s.mouseClick(newLauncherButton, chromedp.ButtonLeft)
	// For whatever reason, when using a selector, this element is selected twice
	terminalButton := `div:not([aria-hidden="true"]) > div.lm-Widget.p-Widget.jp-Launcher div.jp-LauncherCard[title="Start a new terminal session"]`
	Eventually(terminalButton, "10s").Should(b.Exist())

	// time.Sleep(1 * time.Hour)

	By("Opening a terminal")
	s.mouseClick(terminalButton, chromedp.ButtonLeft)
	// terminal := `div.jp-Terminal[label="notebook content"]`
	terminal := "#jp-Terminal-0"
	Eventually(terminal).Should(b.Exist())

	By("Executing the startup script")
	testTS := time.Now().Unix()
	sentinelButton := fmt.Sprintf(`li[title^="Name: get-example-done-%d"]`, testTS)
	Expect(sentinelButton).ToNot(b.Exist())
	startupScript := fmt.Sprintf("%s TEST_TS='%d' /mnt/host/mlflow-oidc-proxy/integration-test/get-example.sh\n", extraVars, testTS)
	s.mouseClick(terminal)
	// The terminal interface takes a moment to connect to the actual terminal running in the container, if we do this too early, keystrokes are lost
	// Once again, there doesn't appear to be any element we can check for that indicates the terminal is connected
	time.Sleep(2 * time.Second)
	Expect(chromedp.Run(b.Context, KeyEventNoChar(startupScript))).To(Succeed())
	Eventually(sentinelButton, "10m").Should(b.Exist())
	folderButton := `li[title^="Name: mlflow-example"]`
	Expect(folderButton).To(b.Exist())

	By("Opening the example notebook")
	s.mouseClick(folderButton, chromedp.ButtonLeft, chromedp.ClickCount(2))
	notebookButton := `li.jp-DirListing-item[title^="Name: MLflow-example-notebook.ipynb"]`
	Eventually(notebookButton).Should(b.Exist())
	s.mouseClick(notebookButton, chromedp.ButtonLeft, chromedp.ClickCount(2))

	By("Clearing all outputs")
	restartButton := `button[title="Restart Kernel and Run All Cells…"]`
	Eventually(restartButton).Should(b.Exist())
	editButton := `.lm-MenuBar-content > li:nth-child(2)`
	Expect(editButton).To(b.Exist())
	s.mouseClick(editButton, chromedp.ButtonLeft)
	clearButton := `div.lm-Widget.p-Widget.lm-Menu.p-Menu [data-command="editmenu:clear-all"]`
	Eventually(clearButton).Should(b.Exist())
	s.mouseMove(clearButton)
	s.mouseClick(clearButton, chromedp.ButtonLeft)

	By("Restarting the kernel and running the notebook")
	s.mouseClick(restartButton, chromedp.ButtonLeft)
	time.Sleep(1 * time.Second)
	// Potential landmine:
	// 	If the kernel is already started, we get a dialog to confirm the restart
	//  If the kernel is not already started, we get a dialog to select the kernel
	// The two buttons have an intersection of their classes, so this "should" work
	acceptButton := ".jp-Dialog-button.jp-mod-accept"
	Eventually(acceptButton).Should(b.Exist())
	b.Click(acceptButton, chromedp.ButtonLeft)

	cellFmt := func(ix int) string {
		return fmt.Sprintf(`.jp-NotebookPanel > div:nth-child(3) > div:nth-child(%d)`, ix)
	}
	codeCellFmt := func(ix int) string {
		return cellFmt(ix) + ".jp-CodeCell"
	}
	codeCellPromptFmt := func(ix int) string {
		return codeCellFmt(ix) + " .jp-InputArea-prompt"
	}
	codeCellOutputFmt := func(ix int) string {
		return codeCellFmt(ix) + " .jp-Cell-outputWrapper "
	}
	codeCellTextOutputFmt := func(ix int) string {
		return codeCellOutputFmt(ix) + " .jp-OutputArea-output > pre"
	}

	for ix := 1; ix <= 57; ix++ {
		cell := cellFmt(ix)
		Expect(cell).To(b.Exist())
		if !b.HasElement(codeCellFmt(ix)) {
			By(fmt.Sprintf("Ignoring the %dth cell (not code)", ix))
			continue
		}
		By(fmt.Sprintf("Waiting for the %dth cell to start", ix))
		// time.Sleep(1 * time.Second)
		prompt := codeCellPromptFmt(ix)
		b.InvokeOn(prompt, "scrollIntoView")
		Eventually(func() string { return b.InnerText(prompt) }, "2m").ShouldNot(Equal("[ ]:"))

		By(fmt.Sprintf("Waiting for the %dth cell to finish", ix))
		output := codeCellOutputFmt(ix)
		Eventually(output).Should(b.Exist())
		b.InvokeOn(output, "scrollIntoView")
		Eventually(func() string { return b.InnerText(prompt) }, "20m").ShouldNot(Equal("[*]:"))
	}

	By("Parsing the final cell's output as JSON")

	var output PredictionOutput
	Expect(json.Unmarshal([]byte(b.InnerText(codeCellTextOutputFmt(57))), &output)).To(Succeed())
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
	Eventually(experimentButton).Should(b.Exist())
	b.Click(experimentButton)
	Eventually(b.Location, "5s").Should(HavePrefix(fmt.Sprintf("%s/#/experiments/1", mlflowTenantURL)))

	mostRecentRun := `div.ag-pinned-left-cols-container > .ag-row-even:nth-child(1) a`
	Eventually(mostRecentRun, "15s").Should(b.Exist())
	b.Click(mostRecentRun)

	userField := `div[data-test-id="descriptions-item"]:nth-child(4) div[data-test-id="descriptions-item-content"] a`
	Eventually(userField).Should(b.Exist())
	Expect(userField).To(b.HaveInnerText(expectedSubject))
}

func (s *subSuite) cases(robotSecretName string, caSecretName string) {
	var _ = BeforeEach(func() {
		s.sessionSetup()
		s.b.Prepare()
	})
	Describe("Tenant 1", func() {
		It("should execute an mlflow jupyterlab notebook with a generated token", func() {
			apiToken := s.keycloakToken(false)
			s.keycloakLogin(false)

			s.loginAndRunNotebook(fmt.Sprintf(`MLFLOW_TRACKING_TOKEN='%s' MLFLOW_TRACKING_URI='%s' `, apiToken, "https://mlflow.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/"), "tenant-1")
		})

		It("should execute an mlflow jupyterlab notebook with a robot certificate", func(ctx context.Context) {
			robotKey := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotSecretName, "tls.key")
			robotCert := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotSecretName, "tls.crt")
			s.keycloakLogin(false)

			s.loginAndRunNotebook(fmt.Sprintf(`MLFLOW_TRACKING_CLIENT_CERT_AND_KEY='%s' MLFLOW_TRACKING_URI='%s'`, robotKey+"\n"+robotCert, "https://mlflow-api.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/"), "robot-1")
		})
	})

	var _ = Describe("Tenant-2", func() {
		It("Should not have access to the other MLFLow tenant using a generated token", func() {
			b := s.b
			mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-2/", oauth2Proxy.Set["ingress.hostname"])
			b.NavigateWithStatus(mlflowTenantURL, http.StatusForbidden)

		})
		It("Should not have access to the other MLFLow tenant using a robot certificate", func(ctx context.Context) {
			robotKey := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotSecretName, "tls.key")
			robotCert := gk8s.KubectlReturnSecretValue(ctx, &cluster, robotSecretName, "tls.crt")
			robotCA := gk8s.KubectlReturnSecretValue(ctx, &cluster, caSecretName, "ca.crt")

			keypair, err := tls.X509KeyPair([]byte(robotCert), []byte(robotKey))
			Expect(err).ToNot(HaveOccurred())
			pool := x509.NewCertPool()
			Expect(pool.AppendCertsFromPEM([]byte(robotCA))).To(BeTrue())

			mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-2/", oauth2Proxy.Set["ingress.hostname"])
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:      pool,
						Certificates: []tls.Certificate{keypair},
					},
					Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://localhost:8080") },
				},
			}
			resp, err := client.Get(mlflowTenantURL)
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

		gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)

		certManagerID := gk8s.Release(clusterID, &certManager, certManagerImageIDs)

		certsID := gk8s.Manifests(clusterID, &certs, certManagerID)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx, certsID, nginxImageID)

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

		postgresOperatorID := gk8s.Release(clusterID, &postgresOperator, certsID, postgresImageIDs)

		postgresID := gk8s.Manifests(clusterID, &postgres, postgresOperatorID)

		postgresSecretsReadyID := gk8s.ClusterAction(clusterID, "Wait for Postgres Secrets", postgresSecretsReady, postgresID)

		minioID := gk8s.Release(clusterID, &minio, minioImageIDs)

		mlflowIDs := []gingk8s.ReleaseID{
			gk8s.Release(clusterID, &mlflow[0],
				minioID,
				postgresID,
				postgresSecretsReadyID,
				mlflowImageID,
			),
			gk8s.Release(clusterID, &mlflow[1], minioID,
				postgresID,
				postgresSecretsReadyID,
				mlflowImageID,
			),
		}

		keycloakID := gk8s.Release(clusterID, &keycloak, postgresID, waitForIngressWebhookID, keycloakImageID)

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
			redisImageID,
		)

		jupyterhubID := gk8s.Release(clusterID, &jupyterhub,
			keycloakID,
			jupyterhubImageID,
			keycloakSetupID, waitForIngressWebhookID, postgresSecretsReadyID,
		)

		_ = gingk8s.ResourceDependencies{
			Releases: []gingk8s.ReleaseID{
				jupyterhubID,
				oauth2ProxyID,
				mlflowOIDCProxyID,
				mlflowIDs[0],
				mlflowIDs[1],
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		gk8s.Setup(ctx)
	})
	s.cases("robot-1", "test-cert")
})

var _ = Describe("Omnibus setup", Ordered, func() {
	s := subSuite{}
	BeforeAll(func() {
		gspec := gk8s.ForSpec()
		gk8s := gspec

		gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)

		mlflowDepsID := gk8s.Release(clusterID, &mlflowMultitenantDeps, postgresImageIDs, certManagerImageIDs)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx2, nginxImageID) //	certsID,

		gk8s.ClusterAction(
			clusterID,
			"Restart kube ingress proxy",
			restartKubeIngressProxy,
			ingressNginxID,
		)

		waitForIngressWebhookID := gk8s.ClusterAction(clusterID, "Wait for Ingress Webhook", gingk8s.ClusterAction(waitForIngressWebhook), ingressNginxID)

		mlflowID := gk8s.Release(clusterID, &mlflowMultitenant,
			mlflowDepsID,
			oauth2ProxyImageID,
			mlflowOIDCProxyImageID,
			waitForIngressWebhookID,
			mlflowImageID,
			keycloakImageID,
			kubectlImageID,
			minioImageIDs,
			redisImageID,
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

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		gk8s.Setup(ctx)
	})

	s.cases("mlflow-multitenant-robot-robot-1", "mlflow-multitenant-robot-robot-1")
})

var _ = Describe("Omnibus setup in Default Configuration", Ordered, func() {
	BeforeAll(func() {
		gspec := gk8s.ForSpec()
		gk8s := gspec

		gk8s.ClusterAction(clusterID, "Watch Pods", watchPods)

		mlflowDepsID := gk8s.Release(clusterID, &mlflowMultitenantDeps, postgresImageIDs, certManagerImageIDs)

		ingressNginxID := gk8s.Release(clusterID, &ingressNginx2, nginxImageID) //	certsID,

		waitForIngressWebhookID := gk8s.ClusterAction(clusterID, "Wait for Ingress Webhook", gingk8s.ClusterAction(waitForIngressWebhook), ingressNginxID)

		gk8s.Release(clusterID, &mlflowMultitenantDefaults,
			mlflowDepsID,
			oauth2ProxyImageID,
			mlflowOIDCProxyImageID,
			waitForIngressWebhookID,
			mlflowImageID,
			keycloakImageID,
			kubectlImageID,
			minioImageIDs,
			redisImageID,
		)

		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)
		gk8s.Setup(ctx)
	})

	It("Should start", func() {
		// This test deliberately left blank

		// We are just testing that running "helm install" without any additional changes actually starts into a valid state where all of the pods are running
	})
})
