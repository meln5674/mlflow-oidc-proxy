package proxy_test

import (
	"net/http"

	proxy "github.com/meln5674/mlflow-oidc-proxy/pkg/proxy"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func goodTokenTest(mode string, name string, req *http.Request) {
	GinkgoHelper()
	getter, ok := proxy.GetTokenGetter(mode, name)
	Expect(ok).To(BeTrue())
	Expect(getter(req)).To(Equal("token-value"))
}

func badTokenTest(mode string, name string, req *http.Request) {
	GinkgoHelper()
	getter, ok := proxy.GetTokenGetter(mode, name)
	Expect(ok).To(BeTrue())
	Expect(getter(req)).To(BeEmpty())
}

var _ = Describe("Raw Token Mode", func() {
	It("Should extract a token from a matching header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("DummyHeader", "token-value")
		goodTokenTest(proxy.TokenModeRaw, "DummyHeader", r)
	})

	It("Should return an empty string if no header is present", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(proxy.TokenModeRaw, "DummyHeader", r)
	})
})

var _ = Describe("Bearer Token Mode", func() {
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "Bearer token-value")
		goodTokenTest(proxy.TokenModeBearer, "", r)
	})

	It("Should return empty string from an invalid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "some-nonsense token-value")
		badTokenTest(proxy.TokenModeBearer, "", r)
	})

	It("Should return empty string from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(proxy.TokenModeBearer, "", r)
	})
})

var _ = Describe("Basic User Token Mode", func() {
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("token-value", "")
		goodTokenTest(proxy.TokenModeBasicUser, "", r)
	})

	It("Should return empty string from an invalid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "some-nonsense token-value")
		badTokenTest(proxy.TokenModeBasicUser, "", r)
	})

	It("Should return empty string from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(proxy.TokenModeBasicUser, "", r)
	})
})

var _ = Describe("Basic Password Token Mode", func() {
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("", "token-value")
		goodTokenTest(proxy.TokenModeBasicPassword, "", r)
	})

	It("Should return empty string from an invalid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "some-nonsense token-value")
		badTokenTest(proxy.TokenModeBasicPassword, "", r)
	})

	It("Should return empty string from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(proxy.TokenModeBasicPassword, "", r)
	})
})
