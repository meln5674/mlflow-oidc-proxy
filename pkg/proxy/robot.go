package proxy

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v4"
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
