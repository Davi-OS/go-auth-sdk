package authsdk

import (
	"context"
	"net/http"
	"strings"
)

type contextKey int

const claimsContextKey contextKey = iota

// ClaimsFromContext retrieves the claims injected by Authenticate,
// RequirePermission or RequireRole.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}

func (c *Client) authenticateRequest(r *http.Request) (*Claims, error) {
	token := bearerToken(r)
	if token == "" {
		return nil, ErrMissingToken
	}
	return c.Verify(token)
}

func writeUnauthorized(w http.ResponseWriter, err error) {
	http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
}

// Authenticate verifies the bearer access token and injects its claims into
// the request context, without checking any specific permission — useful
// when a handler needs to branch on multiple possible permissions itself.
func (c *Client) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := c.authenticateRequest(r)
		if err != nil {
			writeUnauthorized(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsContextKey, claims)))
	})
}

// RequirePermission wraps a handler, rejecting requests unless the bearer
// access token carries perm within this service's scope.
func (c *Client) RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.authenticateRequest(r)
			if err != nil {
				writeUnauthorized(w, err)
				return
			}
			if !claims.HasPermission(perm) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsContextKey, claims)))
		})
	}
}

// RequireRole is the role-based equivalent of RequirePermission.
func (c *Client) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.authenticateRequest(r)
			if err != nil {
				writeUnauthorized(w, err)
				return
			}
			if !claims.HasRole(role) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsContextKey, claims)))
		})
	}
}
