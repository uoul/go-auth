# Go JWT/JWKS Authenticator

A lightweight Go package for authenticating JSON Web Tokens (JWTs) using a JSON Web Key Set (JWKS) endpoint. This package provides a simple interface to validate tokens and extract user identity claims.

## Features

- Validates JWTs using a remote JWKS endpoint.
- Extracts user identity claims from valid access tokens.
- Automatic caching and periodic refreshing of the JWKS to improve performance.
- Configurable request timeout and JWKS refresh interval.

## Usage

This package defines an interface `IAuthenticator[T]` for type-safe identity extraction and provides a concrete implementation `JwksAuthenticator`.

### Interface

```go
package auth

import "net/http"

type IAuthenticator[T any] interface {
	GetIdentityFromHeader(httpHeaders http.Header, header string) (T, error)
	GetIdentityFromAccessToken(token string) (T, error)
}
```

The generic type `T` represents your application's user identity structure.

### Implementation

The `JwksAuthenticator` struct implements the `IAuthenticator` interface. It is initialized with the URI of a JWKS endpoint.

```go
func NewJwksAuthenticator[T any](jwksUri string) IAuthenticator[T]
```

### Example

```go
// Define your user identity structure
// type UserClaims struct {
//     Sub string `json:"sub"`
//     Name string `json:"name"`
// }

// Create a new authenticator
authenticator := auth.NewJwksAuthenticator[UserClaims]("https://your-oidc-provider/.well-known/jwks.json")

// Extract identity from an HTTP request
identity, err := authenticator.GetIdentityFromHeader(r.Header, "Authorization")
if err != nil {
	// handle error (e.g., unauthorized)
}
// Use the identity (e.g., identity.Sub, identity.Name)
```

## Configuration

The `JwksAuthenticator` has the following default settings:

- **Request Timeout**: 10 seconds for fetching the JWKS.
- **JWKS Refresh Interval**: 10 minutes (600 seconds). The JWKS is fetched on first use and then refreshed automatically after this interval.

## Dependencies

- [github.com/lestrrat-go/jwx/v3](https://github.com/lestrrat-go/jwx/v3) for JWT and JWK handling. [^1][^2]

