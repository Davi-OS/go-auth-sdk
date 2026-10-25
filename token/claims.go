// Package token holds the access-token contract shared by the auth service
// and its consumers: the claims, the JWKS format and the ES256 verifier.
// Signing stays inside the auth service.
package token

import "github.com/golang-jwt/jwt/v5"

// Claims are the custom JWT claims issued by the auth service.
// A token is always scoped to a single system (Audience) and at most one
// organization: Roles and Permissions only include what the subject can do
// within that system, inside that organization.
type Claims struct {
	// OrgID is the organization (tenant) the session acts for. Empty when the
	// user has no organization in the target system. Consuming systems use it
	// to scope their own data.
	OrgID       string   `json:"org,omitempty"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"perms"`
	jwt.RegisteredClaims
}

func (c Claims) HasPermission(perm string) bool {
	for _, p := range c.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}
