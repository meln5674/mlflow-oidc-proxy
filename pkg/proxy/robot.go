package proxy

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

type TokenFromClaims struct {
	Raw   map[string]interface{}
	Inner jwt.Token
}

func (t *TokenFromClaims) UnmarshalJSON(bytes []byte) error {
	claims := make(map[string]interface{})
	err := json.Unmarshal(bytes, &claims)
	if err != nil {
		return err
	}

	t.Raw = claims
	t.Inner = jwt.Token{
		Claims: jwt.MapClaims(claims),
	}
	return nil
}

type Robot struct {
	Name  string              `json:"name"`
	Cert  CertificateFromPath `json:"certPath"`
	Token TokenFromClaims     `json:"token"`
}

func GetRobotCertHTTP(name string, req *http.Request) (*x509.Certificate, bool, error) {
	certStringEsc := req.Header.Get(name)
	if certStringEsc == "" {
		return nil, false, nil
	}
	certString, err := url.QueryUnescape(certStringEsc)
	if err != nil {
		return nil, true, errors.Wrap(err, "Invalid url-encoded certificate in header")
	}
	der, rest := pem.Decode([]byte(certString))
	if der == nil {
		return nil, true, fmt.Errorf("No PEM data found in cert header")
	}
	if len(rest) != 0 {
		return nil, true, fmt.Errorf("Trailing data after PEM certificate cert header")
	}
	cert, err := x509.ParseCertificate(der.Bytes)
	return cert, true, err
}

func GetRobotCertHTTPS(req *http.Request) (*x509.Certificate, bool, error) {
	if len(req.TLS.PeerCertificates) == 0 {
		return nil, false, nil
	}
	return req.TLS.PeerCertificates[0], true, nil

}

func GetRobotCert(name string, https bool, req *http.Request) (*x509.Certificate, bool, error) {
	if https {
		return GetRobotCertHTTPS(req)
	}
	return GetRobotCertHTTP(name, req)
}
