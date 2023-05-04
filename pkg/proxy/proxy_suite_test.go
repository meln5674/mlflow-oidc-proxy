package proxy_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var tokenKey ed25519.PrivateKey
var tokenSigner jwt.SigningMethod = jwt.SigningMethodEdDSA
var fakeMLFlow1 = httptest.NewServer(echoServer("/tenants/tenant-1/", "/api/"))
var fakeMLFlow2 = httptest.NewServer(echoServer("/tenants/tenant-2/", "/api/"))

func TestProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Proxy Suite")
}

var _ = BeforeSuite(func() {
	var err error
	_, tokenKey, err = ed25519.GenerateKey(rand.Reader)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	fakeMLFlow1.Close()
	fakeMLFlow2.Close()
})

type RequestEcho struct {
	Method           string
	URL              *url.URL
	Proto            string
	ProtoMajor       int
	ProtoMinor       int
	Header           http.Header
	Body             []byte
	ContentLength    int64
	TransferEncoding []string
	Host             string
	Trailer          http.Header
	RemoteAddr       string
	RequestURI       string
}

func (r *RequestEcho) FromHTTP(r2 *http.Request) *RequestEcho {

	r.Method = r2.Method
	r.URL = r2.URL
	r.Proto = r2.Proto
	r.ProtoMajor = r2.ProtoMajor
	r.ProtoMinor = r2.ProtoMinor
	r.Header = r2.Header
	if r2.Body != nil {
		conLen := r2.ContentLength
		if conLen < 0 {
			conLen = 0
		}
		buf := bytes.NewBuffer(make([]byte, 0, conLen))
		io.Copy(buf, r2.Body)
		r.Body = buf.Bytes()
	}
	r.ContentLength = r2.ContentLength
	copy(r.TransferEncoding, r2.TransferEncoding)
	r.Trailer = r2.Trailer
	r.RemoteAddr = r2.RemoteAddr
	r.RequestURI = r2.RequestURI
	return r
}

func echoServer(staticPrefixes ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		GinkgoRecover()
		found := false
		for _, prefix := range staticPrefixes {
			if strings.HasPrefix(r.URL.Path, prefix) {
				found = true
				break
			}
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		r2 := new(RequestEcho).FromHTTP(r)
		Expect(json.NewEncoder(w).Encode(r2)).To(Succeed())
	})
}
