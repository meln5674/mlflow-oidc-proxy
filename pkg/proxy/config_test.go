package proxy_test

import (
	"encoding/json"

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
			Expect(config.OIDC.AccessTokenHeader).To(Equal(proxy.DefaultAccessTokenHeader))
		})
	})

	When("parsing a complete JSON document", func() {
		BeforeEach(func() {
			config = new(proxy.ProxyConfig).Init()
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
						"accessTokenHeader": "X-My-Custom-Header",
						"policy": "{{ eq 1 2 }}"
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
			Expect(config.OIDC.AccessTokenHeader).To(Equal("X-My-Custom-Header"))
			Expect(config.OIDC.Policy.Raw).To(Equal("{{ eq 1 2 }}"))

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
})
