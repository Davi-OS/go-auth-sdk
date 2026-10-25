package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
)

// JWK is the subset of RFC 7517 needed for EC (ES256) public keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyToJWK encodes an ES256 public key as a JWK, identified by kid so
// consumers can pick the right key during rotation.
func PublicKeyToJWK(kid string, pub *ecdsa.PublicKey) JWK {
	size := (pub.Curve.Params().BitSize + 7) / 8
	x := pub.X.FillBytes(make([]byte, size))
	y := pub.Y.FillBytes(make([]byte, size))
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
		Use: "sig",
		Kid: kid,
		Alg: "ES256",
	}
}

// JWKToPublicKey decodes a JWK back into an ECDSA public key, used by
// consumers to build the key set passed to NewVerifier.
func JWKToPublicKey(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, errors.New("token: unsupported jwk type, expected EC P-256")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// KeySetFromJWKS builds the kid -> public key map expected by NewVerifier.
func KeySetFromJWKS(jwks JWKS) (map[string]*ecdsa.PublicKey, error) {
	keys := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		pub, err := JWKToPublicKey(jwk)
		if err != nil {
			return nil, err
		}
		keys[jwk.Kid] = pub
	}
	return keys, nil
}
