package proxy_test

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v4"
	proxy "github.com/meln5674/mlflow-oidc-proxy/pkg/proxy"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	var config *proxy.ProxyConfig
	When("parsing a blank JSON document", func() {
		BeforeEach(func() {
			config = new(proxy.ProxyConfig).Init()
			Expect(json.Unmarshal([]byte("{}"), &config)).To(Succeed())
			Expect(config.ApplyDefaults()).To(Succeed())
		})

		It("should set the defaults", func() {
			Expect(config.HTTP.Address.URL.Raw).To(Equal(proxy.DefaultAddress))
			Expect(config.HTTP.ExternalURL.Raw).To(Equal("http://" + proxy.DefaultAddress))
			Expect(config.HTTP.TenantsPath).To(Equal(proxy.DefaultTenantsPath))
			Expect(config.MLFlow.Tenants).To(HaveLen(0))
			Expect(config.TLS.Enabled).To(BeFalse())
			Expect(config.OIDC.TokenHeader).To(Equal(proxy.DefaultTokenHeader))
			Expect(config.OIDC.TokenMode).To(Equal(proxy.DefaultTokenMode))
			Expect(config.OIDC.ExtraVariables).To(BeNil())
			Expect(config.Robots.CertificateHeader).To(Equal(proxy.DefaultCertificateHeader))
		})
	})

	When("parsing a complete JSON document", func() {
		BeforeEach(func() {
			config = new(proxy.ProxyConfig).Init()
			// This doc's tokenHeader/Mode is not actually a valid combination,
			// but we are just testing if it parses something other than the default
			Expect(json.Unmarshal([]byte(`
				{
					"http": {
						"address": "1.2.3.4:5",
						"externalURL": "https://some.external.url",
						"tenantsPath": "/something-else/"
					},
					"mlflow": {
						"tenants": [
							{
								"id": "tenant-1",
								"name": "A tenant",
								"upstream": "https://a.hostname/with/a/subpath?and=query"
							},
							{
								"id": "tenant-2",
								"name": "Another tenant",
								"upstream": "http://5.6.7.8"
							}
						]
					},
					"tls": {
						"enabled": true,
						"certFile": "/foo/bar.crt",
						"keyFile": "baz/qux.key"
					},
					"oidc": {
						"policy": "{{ eq 1 2 }}",
						"tokenHeader": "X-My-Custom-Header",
						"tokenMode": "bearer",
						"extraVariables": { "foo": ["bar"], "baz": 1, "qux": 3.5 }
					},
					"robots": {
						"certificateHeader": "X-Another-Custom-Header",
						"robots": [
							{
								"name": "robot-1",
								"certPath": "../../integration-test/test-cert-1.pem",
								"token": { "claim-1": "value-1", "claim-2": "value-2" }
							},
							{
								"name": "robot-2",
								"certPath": "../../integration-test/test-cert-2.pem",
								"token": { "claim-3": "value-3", "claim-4": "value-4" }
							}
						]
					}
				}
			`), &config)).To(Succeed())
			Expect(config.ApplyDefaults()).To(Succeed())
		})

		It("should correctly parse it", func() {
			Expect(config.HTTP.Address.String()).To(Equal("1.2.3.4:5"))
			Expect(config.HTTP.ExternalURL.Inner.String()).To(Equal("https://some.external.url"))
			Expect(config.HTTP.TenantsPath).To(Equal("/something-else/"))
			Expect(config.MLFlow.Tenants).To(HaveLen(2))
			Expect(config.MLFlow.Tenants[0].ID).To(Equal("tenant-1"))
			Expect(config.MLFlow.Tenants[0].Name).To(Equal("A tenant"))
			Expect(config.MLFlow.Tenants[0].Upstream.Inner.String()).To(Equal("https://a.hostname/with/a/subpath?and=query"))
			Expect(config.MLFlow.Tenants[1].ID).To(Equal("tenant-2"))
			Expect(config.MLFlow.Tenants[1].Name).To(Equal("Another tenant"))
			Expect(config.MLFlow.Tenants[1].Upstream.Inner.String()).To(Equal("http://5.6.7.8"))
			Expect(config.TLS.Enabled).To(BeTrue())
			Expect(config.TLS.CertFile).To(Equal("/foo/bar.crt"))
			Expect(config.TLS.KeyFile).To(Equal("baz/qux.key"))
			Expect(config.OIDC.TokenHeader).To(Equal("X-My-Custom-Header"))
			Expect(config.OIDC.TokenMode).To(Equal(proxy.TokenModeBearer))
			Expect(config.OIDC.Policy.Raw).To(Equal("{{ eq 1 2 }}"))
			Expect(config.OIDC.ExtraVariables).To(HaveKeyWithValue("foo", HaveExactElements("bar")))
			Expect(config.OIDC.ExtraVariables).To(HaveKeyWithValue("baz", BeNumerically("==", 1)))
			Expect(config.OIDC.ExtraVariables).To(HaveKeyWithValue("qux", BeNumerically("==", 3.5)))
			Expect(config.Robots.CertificateHeader).To(Equal("X-Another-Custom-Header"))
			Expect(config.Robots.Robots).To(HaveLen(2))
			Expect(config.Robots.Robots[0].Name).To(Equal("robot-1"))
			// TODO: Verify certificate matches
			Expect(config.Robots.Robots[0].Cert.Inner).ToNot(BeNil())
			Expect(config.Robots.Robots[0].Token.Inner.Claims).To(HaveKeyWithValue("claim-1", "value-1"))
			Expect(config.Robots.Robots[0].Token.Inner.Claims).To(HaveKeyWithValue("claim-2", "value-2"))
			Expect(config.Robots.Robots[1].Name).To(Equal("robot-2"))
			// TODO: Verify certificate matches
			Expect(config.Robots.Robots[1].Cert.Inner).ToNot(BeNil())
			Expect(config.Robots.Robots[1].Token.Inner.Claims).To(HaveKeyWithValue("claim-3", "value-3"))
			Expect(config.Robots.Robots[1].Token.Inner.Claims).To(HaveKeyWithValue("claim-4", "value-4"))
		})
	})

	It("should fail to parse an invalid address", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"http": {
				"address": "%%%%"
			}
		}`), &config)).ToNot(Succeed())
	})

	It("should fail to parse something other than a string as an address", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"http": {
				"address": []
			}
		}`), &config)).ToNot(Succeed())
	})

	It("should fail to parse an invalid url", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"http": {
				"externalURL": "cache_object:foo/bar"
			}
		}`), &config)).ToNot(Succeed())
	})

	It("should fail to parse something other than a string as a url", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"http": {
				"externalURL": []
			}
		}`), &config)).ToNot(Succeed())
	})

	It("should fail to parse an invalid template", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"oidc": {
				"policy": "{{"
			}
		}`), &config)).ToNot(Succeed())
	})

	It("should fail to parse something other than a string as a template", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"oidc": {
				"policy": []
			}
		}`), &config)).ToNot(Succeed())
	})

	It("should correctly provide extra variables", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"oidc": {
				"getSubject": "{{ index .ExtraVariables.foo.Bar 2 }}",
				"extraVariables": { "foo": { "Bar": [ 0, 1, "baz" ] } }
			}
		}`), &config)).To(Succeed())

		Expect(config.ApplyDefaults()).To(Succeed())
		p, err := proxy.NewProxy(*config, proxy.ProxyOptions{})
		Expect(err).ToNot(HaveOccurred())
		sub, err := p.GetSubject(&jwt.Token{Claims: jwt.MapClaims{}})
		Expect(err).ToNot(HaveOccurred())
		Expect(sub).To(Equal("baz"))
	})

	It("should provide intersection function", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"oidc": {
				"getSubject": "{{ intersection (list 1 2 3) (list 2 3 4) | toJson }}"
			}
		}`), &config)).To(Succeed())

		Expect(config.ApplyDefaults()).To(Succeed())
		p, err := proxy.NewProxy(*config, proxy.ProxyOptions{})
		Expect(err).ToNot(HaveOccurred())
		sub, err := p.GetSubject(&jwt.Token{Claims: jwt.MapClaims{}})
		Expect(err).ToNot(HaveOccurred())
		Expect(sub).To(Equal(`[2,3]`))
	})

	It("should provide hasIntersection function", func() {
		config = new(proxy.ProxyConfig).Init()
		Expect(json.Unmarshal([]byte(`{
			"oidc": {
				"getSubject": "{{ hasIntersection (list 1 2 3) (list 2 3 4) | toJson }}"
			}
		}`), &config)).To(Succeed())

		Expect(config.ApplyDefaults()).To(Succeed())
		p, err := proxy.NewProxy(*config, proxy.ProxyOptions{})
		Expect(err).ToNot(HaveOccurred())
		sub, err := p.GetSubject(&jwt.Token{Claims: jwt.MapClaims{}})
		Expect(err).ToNot(HaveOccurred())
		Expect(sub).To(Equal(`true`))
	})
})
