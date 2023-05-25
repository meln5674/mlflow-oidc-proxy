package proxy_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type suiteCommon struct {
	TokenKey       ed25519.PrivateKey
	RobotCerts     []*x509.Certificate
	RobotCertPEMs  []string
	serverCert     *x509.Certificate
	ServerCertPath string
	ServerCertPEM  string
	serverKey      crypto.PrivateKey
	ServerKeyPath  string
	ServerKeyPEM   string
}

var suiteCommonVars suiteCommon
var tokenSigner jwt.SigningMethod = jwt.SigningMethodEdDSA
var fakeMLFlow1 = httptest.NewServer(echoServer("/tenants/tenant-1/", "/api/"))
var fakeMLFlow2 = httptest.NewServer(echoServer("/tenants/tenant-2/", "/api/"))

func TestProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Proxy Suite")
}

func beforeSuiteGlobal() []byte {
	var err error
	_, suiteCommonVars.TokenKey, err = ed25519.GenerateKey(rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	suiteCommonVars.RobotCerts = make([]*x509.Certificate, 3)
	suiteCommonVars.RobotCertPEMs = make([]string, 3)

	suiteCommonVars.serverCert = &x509.Certificate{
		SerialNumber: big.NewInt(int64(1000)),
		Subject: pkix.Name{
			Organization: []string{"MLFlow OIDC Proxy Unit Tests"},
			Country:      []string{"US"},
			Locality:     []string{"Cyberspace"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	Expect(err).ToNot(HaveOccurred())
	suiteCommonVars.serverCert.Raw, err = x509.CreateCertificate(
		rand.Reader,
		suiteCommonVars.serverCert,
		suiteCommonVars.serverCert,
		&serverKey.PublicKey,
		serverKey,
	)
	Expect(err).ToNot(HaveOccurred())

	certFile, err := os.CreateTemp("", "")
	Expect(err).ToNot(HaveOccurred())
	defer certFile.Close()
	_, err = certFile.Write(suiteCommonVars.serverCert.Raw)
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() { os.Remove(certFile.Name()) })
	suiteCommonVars.ServerCertPath = certFile.Name()
	serverCertPEM := new(bytes.Buffer)
	pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: suiteCommonVars.serverCert.Raw,
	})
	suiteCommonVars.ServerCertPEM = string(serverCertPEM.Bytes())

	keyFile, err := os.CreateTemp("", "")
	Expect(err).ToNot(HaveOccurred())
	defer keyFile.Close()
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})
	_, err = keyFile.Write(keyPEM.Bytes())
	Expect(err).ToNot(HaveOccurred())
	suiteCommonVars.ServerKeyPEM = string(keyPEM.Bytes())
	DeferCleanup(func() { os.Remove(keyFile.Name()) })
	suiteCommonVars.ServerKeyPath = keyFile.Name()
	suiteCommonVars.serverKey = serverKey

	for ix := range []int{0, 1, 2} {

		suiteCommonVars.RobotCerts[ix] = &x509.Certificate{
			SerialNumber: big.NewInt(int64(1000 + ix + 1)),
			Subject: pkix.Name{
				Organization: []string{"MLFlow OIDC Proxy Unit Tests"},
				Country:      []string{"US"},
				Locality:     []string{"Cyberspace"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		robotPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		Expect(err).ToNot(HaveOccurred())
		suiteCommonVars.RobotCerts[ix].Raw, err = x509.CreateCertificate(rand.Reader, suiteCommonVars.RobotCerts[ix], suiteCommonVars.RobotCerts[ix], &robotPrivKey.PublicKey, robotPrivKey)
		Expect(err).ToNot(HaveOccurred())
		Expect(suiteCommonVars.RobotCerts[ix].Raw).ToNot(HaveLen(0))
		robotCertPEMBytes := new(bytes.Buffer)
		pem.Encode(robotCertPEMBytes, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: suiteCommonVars.RobotCerts[ix].Raw,
		})
		suiteCommonVars.RobotCertPEMs[ix] = string(robotCertPEMBytes.Bytes())
	}

	Expect(suiteCommonVars.ServerCertPEM).ToNot(BeEmpty())
	Expect(suiteCommonVars.ServerKeyPEM).ToNot(BeEmpty())

	commonBytes, err := json.Marshal(&suiteCommonVars)
	Expect(err).ToNot(HaveOccurred())
	return commonBytes
}

func beforeSuiteLocal(commonBytes []byte) {
	Expect(json.Unmarshal(commonBytes, &suiteCommonVars)).To(Succeed())

	GinkgoWriter.Printf("%#v\n", suiteCommonVars)

	Expect(suiteCommonVars.ServerCertPEM).ToNot(BeEmpty())
	Expect(suiteCommonVars.ServerKeyPEM).ToNot(BeEmpty())

	cert, err := tls.X509KeyPair([]byte(suiteCommonVars.ServerCertPEM), []byte(suiteCommonVars.ServerKeyPEM))
	Expect(err).ToNot(HaveOccurred())

	suiteCommonVars.serverCert = cert.Leaf
	suiteCommonVars.serverKey = cert.PrivateKey
}

var _ = SynchronizedBeforeSuite(beforeSuiteGlobal, beforeSuiteLocal)

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
