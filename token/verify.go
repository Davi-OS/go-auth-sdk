package token

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultIssuer is the iss claim the auth service uses when its
// AUTH_ISSUER is not set. Deployments should set their own (e.g. the
// service's public URL) and pass it to NewVerifier.
const DefaultIssuer = "auth-service"

var ErrUnknownKey = errors.New("token: unknown key id")
var ErrInvalidAudience = errors.New("token: token must have exactly one audience")

// Verifier validates access tokens against a set of trusted public keys,
// keyed by kid so multiple keys can be trusted at once during rotation.
type Verifier struct {
	issuer string
	keys   map[string]*ecdsa.PublicKey
}

func NewVerifier(issuer string, keys map[string]*ecdsa.PublicKey) *Verifier {
	return &Verifier{issuer: issuer, keys: keys}
}

// Verify checks signature, issuer, expiration and audience (the system the
// caller expects the token to be scoped to). It does not check revocation —
// that is layered on top by the caller using a separate revocation cache.
func (v *Verifier) Verify(tokenString string, expectedAudience string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(expectedAudience),
	)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// VerifyAnyAudience is Verify for endpoints that serve users of every system
// (e.g. /me): the expected audience is the one the token itself claims, which
// is safe because the signature, issuer and expiry are still fully checked.
func (v *Verifier) VerifyAnyAudience(tokenString string) (*Claims, error) {
	unverified := &Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, unverified); err != nil {
		return nil, err
	}
	if len(unverified.Audience) != 1 {
		return nil, ErrInvalidAudience
	}
	return v.Verify(tokenString, unverified.Audience[0])
}
