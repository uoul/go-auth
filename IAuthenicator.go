package auth

import "net/http"

type IAuthenticator[T any] interface {
	GetIdentityFromHeader(httpHeaders http.Header, header string) (T, error)
	GetIdentityFromAccessToken(token string) (T, error)
}
