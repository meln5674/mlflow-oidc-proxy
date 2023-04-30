package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"
	"unicode"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type PredictionOutput struct {
	Predictions []float64
}

func nodes(sel interface{}) []*cdp.Node {
	GinkgoHelper()
	var toReturn []*cdp.Node
	Expect(chromedp.Run(b.Context, chromedp.QueryAfter(sel, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
		toReturn = nodes
		return nil
	}))).To(Succeed())
	return toReturn
}

func mouseClick(sel interface{}, opts ...chromedp.MouseOption) {
	GinkgoHelper()
	Expect(chromedp.Run(b.Context, chromedp.QueryAfter(sel, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
		Expect(nodes).To(HaveLen(1))
		return chromedp.MouseClickNode(nodes[0], opts...).Do(ctx)
	}))).To(Succeed())
}

func mouseMove(sel interface{}, opts ...chromedp.MouseOption) {
	GinkgoHelper()
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

var _ = BeforeEach(func() {
	b.Prepare()
}, OncePerOrdered)

func keycloakToken(needCredentials bool) string {
	GinkgoHelper()
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

func keycloakLogin(needCredentials bool) {
	GinkgoHelper()
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

var _ = Describe("Tenant 1", func() {
	It("should execute an mlflow jupyterlab notebook with a generated token", func() {
		apiToken := keycloakToken(false)
		keycloakLogin(false)

		By("Going to Jupyterhub")
		b.Navigate(fmt.Sprintf("https://%s/", jupyterhub.Set["ingress.hosts[0]"]))
		Eventually(".btn.btn-jupyter.btn-lg").Should(b.Exist())
		b.Click(".btn.btn-jupyter.btn-lg")

		By("Navigating to the workspace root")
		// The file browser loads so slowly, that by the time we've opened a terminal on a pre-warmed instance, it re-navigates to the cached location after we've already clicked the root button
		// There doesn't seem to be any obvious element whose existence indicates the browser is actually finished loading
		time.Sleep(15 * time.Second)
		rootFolderButton := ".jp-BreadCrumbs-home"
		Eventually(rootFolderButton).Should(b.Exist())
		mouseClick(rootFolderButton, chromedp.ButtonLeft)
		folder := `.jp-BreadCrumbs [title="mlflow-example"]`
		Eventually(folder).ShouldNot(b.Exist())

		By("Opening a new launcher")
		fileButton := `div[role="banner"] .lm-MenuBar-content > li:nth-child(1)`
		Eventually(fileButton).Should(b.Exist())
		mouseClick(fileButton, chromedp.ButtonLeft)
		time.Sleep(1 * time.Second)
		launcherButton := `div.lm-Widget.p-Widget.lm-Menu.p-Menu [data-command="filebrowser:create-main-launcher"]`
		Eventually(launcherButton).Should(b.Exist())
		mouseMove(launcherButton)
		// Expect(chromedp.Run(b.Context, chromedp.QueryAfter(launcherButton, func(ctx context.Context, id cdpruntime.ExecutionContextID, nodes ...*cdp.Node) error {
		// 	Expect(nodes).To(HaveLen(1))
		// 	return MouseMoveNode(nodes[0]).Do(ctx)
		// }))).To(Succeed())
		//time.Sleep(5 * time.Second)
		mouseClick(launcherButton, chromedp.ButtonLeft)

		// mouseClick(newLauncherButton, chromedp.ButtonLeft)
		// For whatever reason, when using a selector, this element is selected twice
		// terminalButton := `div.jp-LauncherCard[title="Start a new terminal session"]`
		terminalButton := b.XPath(`/html/body/div[1]/div[3]/div[2]/div[1]/div[3]/div[4]/div[3]/div/div/div[4]/div[2]/div[1]`)
		Eventually(terminalButton, "10s").Should(b.Exist())

		// time.Sleep(1 * time.Hour)

		By("Opening a terminal")
		mouseClick(terminalButton, chromedp.ButtonLeft)
		// terminal := `div.jp-Terminal[label="notebook content"]`
		terminal := "#jp-Terminal-0"
		Eventually(terminal).Should(b.Exist())

		By("Executing the startup script")
		testTS := time.Now().Unix()
		sentinelButton := fmt.Sprintf(`li[title^="Name: get-example-done-%d"]`, testTS)
		Expect(sentinelButton).ToNot(b.Exist())
		startupScript := fmt.Sprintf("MLFLOW_TRACKING_TOKEN='%s' TEST_TS='%d' /mnt/host/mlflow-oidc-proxy/integration-test/get-example.sh\n", apiToken, testTS)
		mouseClick(terminal)
		// The terminal interface takes a moment to connect to the actual terminal running in the container, if we do this too early, keystrokes are lost
		// Once again, there doesn't appear to be any element we can check for that indicates the terminal is connected
		time.Sleep(2 * time.Second)
		Expect(chromedp.Run(b.Context, KeyEventNoChar(startupScript))).To(Succeed())
		Eventually(sentinelButton, "2m").Should(b.Exist())
		folderButton := `li[title^="Name: mlflow-example"]`
		Expect(folderButton).To(b.Exist())

		By("Opening the example notebook")
		mouseClick(folderButton, chromedp.ButtonLeft, chromedp.ClickCount(2))
		notebookButton := `li.jp-DirListing-item[title^="Name: MLflow-example-notebook.ipynb"]`
		Eventually(notebookButton).Should(b.Exist())
		mouseClick(notebookButton, chromedp.ButtonLeft, chromedp.ClickCount(2))

		By("Clearing all outputs")
		restartButton := `button[title="Restart Kernel and Run All Cells…"]`
		Eventually(restartButton).Should(b.Exist())
		editButton := `.lm-MenuBar-content > li:nth-child(2)`
		Expect(editButton).To(b.Exist())
		mouseClick(editButton, chromedp.ButtonLeft)
		clearButton := `div.lm-Widget.p-Widget.lm-Menu.p-Menu [data-command="editmenu:clear-all"]`
		Eventually(clearButton).Should(b.Exist())
		mouseMove(clearButton)
		mouseClick(clearButton, chromedp.ButtonLeft)

		By("Restarting the kernel and running the notebook")
		mouseClick(restartButton, chromedp.ButtonLeft)
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
			Eventually(func() string { return b.InnerText(prompt) }, "5m").ShouldNot(Equal("[*]:"))
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
	})
})

var _ = Describe("Tenant-2", func() {
	It("Should not allow access to the other MLFLow tenant", func() {
		mlflowTenantURL := fmt.Sprintf("https://%s/tenants/tenant-2/", oauth2Proxy.Set["ingress.hostname"])
		b.NavigateWithStatus(mlflowTenantURL, http.StatusForbidden)

	})
})
