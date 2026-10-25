package authsdk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Davi-OS/go-auth-sdk/authsdk"
)

func TestRequirePermissionMiddleware(t *testing.T) {
	priv, err := generateKey()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const kid = "test-key"
	fake := newFakeAuthServer(kid, &priv.PublicKey)
	defer fake.Close()

	client, err := authsdk.New(context.Background(), authsdk.Config{
		BaseURL:      fake.URL(),
		Audience:     "billing-system",
		PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	var handlerCalled bool
	protected := client.RequirePermission("invoice:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		claims, ok := authsdk.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in request context")
		} else if claims.Subject != "user-1" {
			t.Errorf("Subject = %q, want user-1", claims.Subject)
		}
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(protected)
	defer ts.Close()

	signer := newTestSigner(kid, priv)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET (no token): %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for missing token", resp.StatusCode)
	}

	tokenNoPerm, err := signer.Sign("user-1", "billing-system", "", nil, []string{"other:action"}, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	resp, err = doWithBearer(ts.URL, tokenNoPerm)
	if err != nil {
		t.Fatalf("GET (wrong permission): %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing permission", resp.StatusCode)
	}

	token, err := signer.Sign("user-1", "billing-system", "", nil, []string{"invoice:read"}, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	resp, err = doWithBearer(ts.URL, token)
	if err != nil {
		t.Fatalf("GET (correct permission): %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !handlerCalled {
		t.Error("expected the wrapped handler to run")
	}
}

func doWithBearer(url, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}
