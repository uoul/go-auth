# Go JWT/JWKS Authenticator

A lightweight Go package for authenticating JSON Web Tokens (JWTs) using a JSON Web Key Set (JWKS) endpoint. This package provides a simple interface to validate tokens and extract user identity claims.

## Features

- Validates JWTs using a remote JWKS endpoint.
- Extracts user identity claims from valid access tokens.
- Automatic caching and periodic refreshing of the JWKS to improve performance.
- Keeps serving the cached JWKS if a refresh fails.
- Configurable request timeout and JWKS refresh interval.
- Safe for concurrent use.

## Usage

This package defines an interface `IAuthenticator[T]` for type-safe identity extraction and provides a concrete implementation `JwksAuthenticator`.

### Interface

```go
package auth

type IAuthenticator[T any] interface {
	GetIdentity(token string) (T, error)
}
```

The generic type `T` represents your application's user identity structure. `GetIdentity` verifies the token's signature and registered claims (`exp`, `nbf`, `iat`), then decodes the payload into `T`.

### Implementation

The `JwksAuthenticator` struct implements the `IAuthenticator` interface. It is initialized with the URL of a JWKS endpoint and optional configuration options.

```go
func NewJwksAuthenticator[T any](jwksUrl string, opts ...func(*JwksAuthenticator[T])) *JwksAuthenticator[T]
```

### Example

```go
// Define your user identity structure
type UserClaims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
}

// Create a new authenticator
authenticator := auth.NewJwksAuthenticator[UserClaims](
	"https://your-oidc-provider/.well-known/jwks.json",
	auth.WithJwksTimeout[UserClaims](5*time.Second),
	auth.WithJwksRefreshInterval[UserClaims](1*time.Hour),
)

// Extract the bearer token from an HTTP request
token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
if !found {
	// handle missing/invalid header (e.g., unauthorized)
}

identity, err := authenticator.GetIdentity(token)
if err != nil {
	// handle error (e.g., unauthorized)
}
// Use the identity (e.g., identity.Sub, identity.Name)
```

## Configuration

| Option                        | Default    | Description                                                                 |
| ----------------------------- | ---------- | --------------------------------------------------------------------------- |
| `WithJwksTimeout[T](d)`       | 10 seconds | Timeout for fetching the JWKS.                                              |
| `WithJwksRefreshInterval[T](d)` | 6 hours  | The JWKS is fetched on first use and refreshed after this interval.        |

The type parameter must be given explicitly on the options (e.g. `auth.WithJwksTimeout[UserClaims](...)`), since Go cannot infer it from the arguments.

If a refresh fails while a JWKS is already cached, the cached set continues to be used and the refresh is retried after about one minute.

## Dependencies

- [github.com/lestrrat-go/jwx/v4](https://github.com/lestrrat-go/jwx) for JWT and JWK handling.
