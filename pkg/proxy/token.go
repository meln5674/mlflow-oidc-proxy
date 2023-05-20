package proxy

import (
	"net/http"
	"strings"
)

const (
	// HeaderAuthorization is the name of the header to obtain the bearer token from
	HeaderAuthorization = "Authorization"
	// HeaderAuthorizationBearerPrefix is the prefix to the Authorization header if it contains a bearer token
	HeaderAuthorizationBearerPrefix = "Bearer "
)

type TokenMode = string

const (
	TokenModeRaw           = "raw"
	TokenModeBearer        = "bearer"
	TokenModeBasicUser     = "basic-user"
	TokenModeBasicPassword = "basic-password"
)

type TokenGetter func(req *http.Request) string

func GetRawToken(name string) TokenGetter {
	return func(req *http.Request) string {
		return req.Header.Get(name)
	}
}

func GetBearerToken() TokenGetter {
	return func(req *http.Request) string {
		h := req.Header.Get(HeaderAuthorization)
		prefix := HeaderAuthorizationBearerPrefix
		if !strings.HasPrefix(h, prefix) {
			return ""
		}
		return strings.TrimPrefix(h, prefix)
	}
}

func GetBasicUserToken() TokenGetter {
	return func(req *http.Request) string {
		username, _, _ := req.BasicAuth()
		return username
	}
}

func GetBasicPasswordToken() TokenGetter {
	return func(req *http.Request) string {
		_, password, _ := req.BasicAuth()
		return password
	}
}

func GetTokenGetter(mode string, name string) (TokenGetter, bool) {
	switch mode {
	case TokenModeRaw:
		return GetRawToken(name), true
	case TokenModeBearer:
		return GetBearerToken(), true
	case TokenModeBasicUser:
		return GetBasicUserToken(), true
	case TokenModeBasicPassword:
		return GetBasicPasswordToken(), true
	}
	return nil, false
}
