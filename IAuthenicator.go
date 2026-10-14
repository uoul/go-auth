package auth

type IAuthenticator[T any] interface {
	GetIdentity(token string) (T, error)
}
