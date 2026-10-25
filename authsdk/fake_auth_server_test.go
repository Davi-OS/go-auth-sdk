package authsdk_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/Davi-OS/go-auth-sdk/token"
)

type fakeRevokedJTI struct {
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

type fakeUserInvalidation struct {
	UserID        string    `json:"user_id"`
	InvalidBefore time.Time `json:"invalid_before"`
}

type fakeRevocationsResponse struct {
	RevokedJTIs       []fakeRevokedJTI       `json:"revoked_jtis"`
	UserInvalidations []fakeUserInvalidation `json:"user_invalidations"`
}

// fakeAuthServer mimics the two endpoints authsdk.Client depends on, so the
// SDK can be tested without a running instance of the real auth service.
type fakeAuthServer struct {
	mu                sync.Mutex
	revokedJTIs       map[string]time.Time
	userInvalidations map[string]time.Time
	jwks              token.JWKS

	srv *httptest.Server
}

func newFakeAuthServer(kid string, pub *ecdsa.PublicKey) *fakeAuthServer {
	f := &fakeAuthServer{
		revokedJTIs:       map[string]time.Time{},
		userInvalidations: map[string]time.Time{},
		jwks:              token.JWKS{Keys: []token.JWK{token.PublicKeyToJWK(kid, pub)}},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(f.jwks)
	})
	mux.HandleFunc("GET /revocations", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		var resp fakeRevocationsResponse
		for jti, exp := range f.revokedJTIs {
			resp.RevokedJTIs = append(resp.RevokedJTIs, fakeRevokedJTI{JTI: jti, ExpiresAt: exp})
		}
		for uid, before := range f.userInvalidations {
			resp.UserInvalidations = append(resp.UserInvalidations, fakeUserInvalidation{UserID: uid, InvalidBefore: before})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	f.srv = httptest.NewServer(mux)
	return f
}

func (f *fakeAuthServer) URL() string {
	return f.srv.URL
}

func (f *fakeAuthServer) revokeJTI(jti string, expiresAt time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedJTIs[jti] = expiresAt
}

func (f *fakeAuthServer) invalidateUser(userID string, before time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userInvalidations[userID] = before
}

func (f *fakeAuthServer) Close() {
	f.srv.Close()
}
