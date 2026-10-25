package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func sign(t *testing.T, priv *ecdsa.PrivateKey, kid string, aud ...string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, Claims{
		OrgID:       "org-9",
		Roles:       []string{"billing-admin"},
		Permissions: []string{"invoice:read"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Audience:  aud,
			Issuer:    DefaultIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestVerifyThroughJWKS(t *testing.T) {
	priv := newKey(t)
	keys, err := KeySetFromJWKS(JWKS{Keys: []JWK{PublicKeyToJWK("kid-1", &priv.PublicKey)}})
	if err != nil {
		t.Fatalf("KeySetFromJWKS: %v", err)
	}

	claims, err := NewVerifier(DefaultIssuer, keys).Verify(sign(t, priv, "kid-1", "billing-system"), "billing-system")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.OrgID != "org-9" || claims.Subject != "user-123" {
		t.Errorf("claims = %+v", claims)
	}
	if !claims.HasPermission("invoice:read") || !claims.HasRole("billing-admin") {
		t.Errorf("missing permission or role: %+v", claims)
	}
}

func TestVerifyRejects(t *testing.T) {
	priv := newKey(t)
	v := NewVerifier(DefaultIssuer, map[string]*ecdsa.PublicKey{"kid-1": &priv.PublicKey})

	if _, err := v.Verify(sign(t, priv, "kid-1", "billing-system"), "report-system"); err == nil {
		t.Error("wrong audience: expected an error")
	}
	if _, err := v.Verify(sign(t, priv, "kid-2", "billing-system"), "billing-system"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown kid: err = %v, want ErrUnknownKey", err)
	}
	if _, err := NewVerifier("https://other", v.keys).Verify(sign(t, priv, "kid-1", "billing-system"), "billing-system"); err == nil {
		t.Error("wrong issuer: expected an error")
	}
}

func TestVerifyAnyAudience(t *testing.T) {
	priv := newKey(t)
	v := NewVerifier(DefaultIssuer, map[string]*ecdsa.PublicKey{"kid-1": &priv.PublicKey})

	claims, err := v.VerifyAnyAudience(sign(t, priv, "kid-1", "report-system"))
	if err != nil {
		t.Fatalf("VerifyAnyAudience: %v", err)
	}
	if claims.Audience[0] != "report-system" {
		t.Errorf("aud = %v", claims.Audience)
	}
	if _, err := v.VerifyAnyAudience(sign(t, priv, "kid-1", "a", "b")); !errors.Is(err, ErrInvalidAudience) {
		t.Errorf("two audiences: err = %v, want ErrInvalidAudience", err)
	}
}
