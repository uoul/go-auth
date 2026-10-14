package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

var _ IAuthenticator[any] = (*JwksAuthenticator[any])(nil)

// -------------------------------------------------------------------
// Types
// -------------------------------------------------------------------

type JwksAuthenticator[T any] struct {
	jwksUrl         string
	jwkSet          jwk.Set
	lastJwksRefresh time.Time
	mu              sync.RWMutex

	timeout             time.Duration
	jwksRefreshInterval time.Duration
}

// -------------------------------------------------------------------
// Public Methods/Functions
// -------------------------------------------------------------------

// GetIdentity implements [IAuthenticator].
func (j *JwksAuthenticator[T]) GetIdentity(token string) (T, error) {
	var identity T

	jwkSet, err := j.getJwkSet()
	if err != nil {
		return identity, err
	}

	// Verify signature and validate registered claims (exp, nbf, iat)
	if _, err := jwt.Parse(
		[]byte(token),
		jwt.WithKeySet(jwkSet),
		jwt.WithVerify(true),
		jwt.WithValidate(true),
	); err != nil {
		return identity, fmt.Errorf("invalid token: %w", err)
	}

	// Token is verified - decode payload into T
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return identity, fmt.Errorf("invalid token: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return identity, fmt.Errorf("failed to decode token payload: %w", err)
	}
	if err := json.Unmarshal(payload, &identity); err != nil {
		return identity, fmt.Errorf("failed to parse token payload: %w", err)
	}
	return identity, nil
}

// -------------------------------------------------------------------
// Private Methods/Functions
// -------------------------------------------------------------------

func (j *JwksAuthenticator[T]) getJwkSet() (jwk.Set, error) {
	// Fast path: cached set is still fresh
	j.mu.RLock()
	set, fresh := j.jwkSet, time.Since(j.lastJwksRefresh) < j.jwksRefreshInterval
	j.mu.RUnlock()
	if set != nil && fresh {
		return set, nil
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	// Re-check: another goroutine may have refreshed while we waited
	if j.jwkSet != nil && time.Since(j.lastJwksRefresh) < j.jwksRefreshInterval {
		return j.jwkSet, nil
	}

	newSet, err := j.fetchJwkSet()
	if err != nil {
		if j.jwkSet != nil {
			// Serve stale keys on failure and back off before retrying
			j.lastJwksRefresh = time.Now().Add(-j.jwksRefreshInterval + time.Minute)
			return j.jwkSet, nil
		}
		return nil, err
	}
	j.jwkSet = newSet
	j.lastJwksRefresh = time.Now()
	return newSet, nil
}

func (j *JwksAuthenticator[T]) fetchJwkSet() (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(context.Background(), j.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.jwksUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwks request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch jwks: unexpected status %s", res.Status)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks response: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwks: %w", err)
	}
	return set, nil
}

// -------------------------------------------------------------------
// Options
// -------------------------------------------------------------------

func WithJwksTimeout[T any](t time.Duration) func(*JwksAuthenticator[T]) {
	return func(ja *JwksAuthenticator[T]) {
		ja.timeout = t
	}
}

func WithJwksRefreshInterval[T any](t time.Duration) func(*JwksAuthenticator[T]) {
	return func(ja *JwksAuthenticator[T]) {
		ja.jwksRefreshInterval = t
	}
}

// -------------------------------------------------------------------
// Constructor
// -------------------------------------------------------------------

func NewJwksAuthenticator[T any](jwksUrl string, opts ...func(*JwksAuthenticator[T])) *JwksAuthenticator[T] {
	a := &JwksAuthenticator[T]{
		jwksUrl:             jwksUrl,
		lastJwksRefresh:     time.Time{},
		timeout:             10 * time.Second,
		jwksRefreshInterval: 6 * time.Hour,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}
