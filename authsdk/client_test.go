package authsdk_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Davi-OS/go-auth-sdk/authsdk"
)

func TestClientVerifiesValidToken(t *testing.T) {
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

	signer := newTestSigner(kid, priv)
	token, err := signer.Sign("user-1", "billing-system", "", []string{"billing-admin"}, []string{"invoice:read"}, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := client.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
	if !claims.HasPermission("invoice:read") {
		t.Error("expected invoice:read permission")
	}
}

func TestClientRejectsWrongAudience(t *testing.T) {
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

	signer := newTestSigner(kid, priv)
	token, err := signer.Sign("user-1", "report-system", "", nil, nil, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := client.Verify(token); err == nil {
		t.Fatal("expected error verifying a token scoped to a different system")
	}
}

func TestClientPicksUpJTIRevocationViaPolling(t *testing.T) {
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
		PollInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	signer := newTestSigner(kid, priv)
	token, err := signer.Sign("user-1", "billing-system", "", nil, nil, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := client.Verify(token)
	if err != nil {
		t.Fatalf("Verify (before revocation): %v", err)
	}

	fake.revokeJTI(claims.ID, time.Now().Add(time.Minute))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Verify(token); errors.Is(err, authsdk.ErrTokenRevoked) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected token to become revoked after the poller picked up the jti revocation")
}

func TestClientPicksUpUserInvalidationViaPolling(t *testing.T) {
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
		PollInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	signer := newTestSigner(kid, priv)
	token, err := signer.Sign("user-42", "billing-system", "", nil, nil, time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := client.Verify(token); err != nil {
		t.Fatalf("Verify (before logout-all): %v", err)
	}

	time.Sleep(5 * time.Millisecond) // ensure invalidation timestamp is strictly after the token's iat
	fake.invalidateUser("user-42", time.Now())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Verify(token); errors.Is(err, authsdk.ErrTokenRevoked) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected token to become revoked after the poller picked up the user invalidation")
}
