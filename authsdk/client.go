// Package authsdk is the client library consuming services import to
// validate access tokens issued by the auth service, entirely locally
// (signature + claims), with revocation propagated via lightweight
// background polling instead of a round-trip on every request.
package authsdk

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Davi-OS/go-auth-sdk/token"
)

// Claims re-exports token.Claims so most consumers only import authsdk.
type Claims = token.Claims

// pollOverlap re-requests a small window before the last successful poll,
// tolerating minor clock skew between this process and the auth service.
const pollOverlap = 2 * time.Second

type Config struct {
	// BaseURL is the auth service's base URL, e.g. "https://auth.internal".
	BaseURL string
	// Audience is this consuming service's own system slug. Access tokens
	// are only accepted if their aud claim matches this exactly.
	Audience string
	// PollInterval controls how often the revocation cache refreshes.
	// Defaults to 5 seconds.
	PollInterval time.Duration
	// HTTPClient is used for calls to the auth service. Defaults to
	// http.DefaultClient.
	HTTPClient *http.Client
	// Issuer is the iss claim tokens must carry: the auth service's
	// AUTH_ISSUER. Defaults to "auth-service".
	Issuer string
}

type Client struct {
	baseURL      string
	audience     string
	pollInterval time.Duration
	httpClient   *http.Client

	verifier *token.Verifier

	mu               sync.RWMutex
	revokedJTIs      map[string]time.Time // jti -> expires_at, for pruning
	userInvalidAfter map[string]time.Time // user_id -> invalid_before
	lastPoll         time.Time

	cancel context.CancelFunc
	done   chan struct{}
}

// New fetches the auth service's public signing key(s) and starts a
// background poller that keeps a local revocation cache fresh, so Verify
// never needs a round-trip to the auth service per request.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("authsdk: BaseURL is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("authsdk: Audience is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	c := &Client{
		baseURL:          strings.TrimRight(cfg.BaseURL, "/"),
		audience:         cfg.Audience,
		pollInterval:     cfg.PollInterval,
		httpClient:       cfg.HTTPClient,
		revokedJTIs:      make(map[string]time.Time),
		userInvalidAfter: make(map[string]time.Time),
	}

	keys, err := c.fetchJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("authsdk: fetch jwks: %w", err)
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = token.DefaultIssuer
	}
	c.verifier = token.NewVerifier(issuer, keys)

	if err := c.fetchRevocations(ctx); err != nil {
		return nil, fmt.Errorf("authsdk: initial revocations fetch: %w", err)
	}

	pollCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.done = make(chan struct{})
	go c.pollLoop(pollCtx)

	return c, nil
}

// Close stops the background revocation poller. Call it when the consuming
// service shuts down.
func (c *Client) Close() {
	c.cancel()
	<-c.done
}

// Verify validates an access token: signature, issuer, expiration,
// audience (must match this client's Audience) and revocation status
// against the locally cached revocation delta.
func (c *Client) Verify(tokenString string) (*Claims, error) {
	claims, err := c.verifier.Verify(tokenString, c.audience)
	if err != nil {
		return nil, err
	}
	if c.isRevoked(claims) {
		return nil, ErrTokenRevoked
	}
	return claims, nil
}

func (c *Client) isRevoked(claims *Claims) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if _, ok := c.revokedJTIs[claims.ID]; ok {
		return true
	}
	if invalidBefore, ok := c.userInvalidAfter[claims.Subject]; ok {
		if claims.IssuedAt != nil && claims.IssuedAt.Time.Before(invalidBefore) {
			return true
		}
	}
	return false
}

func (c *Client) pollLoop(ctx context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.fetchRevocations(ctx) // best-effort; next tick retries on failure
		}
	}
}

func (c *Client) fetchJWKS(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var jwks token.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	return token.KeySetFromJWKS(jwks)
}

type revocationsResponse struct {
	RevokedJTIs []struct {
		JTI       string    `json:"jti"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"revoked_jtis"`
	UserInvalidations []struct {
		UserID        string    `json:"user_id"`
		InvalidBefore time.Time `json:"invalid_before"`
	} `json:"user_invalidations"`
}

func (c *Client) fetchRevocations(ctx context.Context) error {
	c.mu.RLock()
	since := c.lastPoll
	c.mu.RUnlock()

	reqURL := c.baseURL + "/revocations"
	if !since.IsZero() {
		q := url.Values{}
		q.Set("since", since.Add(-pollOverlap).Format(time.RFC3339))
		reqURL += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var body revocationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}

	now := time.Now()
	c.mu.Lock()
	for _, r := range body.RevokedJTIs {
		c.revokedJTIs[r.JTI] = r.ExpiresAt
	}
	for _, u := range body.UserInvalidations {
		c.userInvalidAfter[u.UserID] = u.InvalidBefore
	}
	c.pruneExpiredLocked(now)
	c.lastPoll = now
	c.mu.Unlock()

	return nil
}

// pruneExpiredLocked drops jti entries whose underlying token has already
// expired naturally — the revocation check becomes moot at that point, so
// keeping the entry around would only leak memory. Caller must hold c.mu.
func (c *Client) pruneExpiredLocked(now time.Time) {
	for jti, expiresAt := range c.revokedJTIs {
		if now.After(expiresAt) {
			delete(c.revokedJTIs, jti)
		}
	}
}
