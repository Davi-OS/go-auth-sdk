package authsdk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Davi-OS/go-auth-sdk/token"
)

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// testSigner issues tokens shaped like the auth service's, so the SDK can be
// tested without depending on the service (signing lives only there).
type testSigner struct {
	kid  string
	priv *ecdsa.PrivateKey
}

func newTestSigner(kid string, priv *ecdsa.PrivateKey) *testSigner {
	return &testSigner{kid: kid, priv: priv}
}

func (s *testSigner) Sign(subject, audience, orgID string, roles, perms []string, ttl time.Duration) (string, error) {
	now := time.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := token.Claims{
		OrgID:       orgID,
		Roles:       roles,
		Permissions: perms,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			Issuer:    token.DefaultIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        base64.RawURLEncoding.EncodeToString(jti),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.priv)
}
