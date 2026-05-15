package sigkeydraft

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/remitly-oss/httpsig-go/keyutil"
)

// OIDCIssuerVerifier validates JWTs by fetching the issuer's
// JWKS from {iss}/.well-known/jwks.json, verifying the JWT signature, and
// validating standard claims (exp, iat).
//
// Only issuers in the allowedIssuers list are accepted. An empty list rejects
// all JWTs.
//
// JWKS responses are cached per issuer with a configurable TTL (default 5
// minutes) to avoid fetching on every request.
type OIDCIssuerVerifier struct {
	allowedIssuers map[string]struct{}
	httpClient     *http.Client
	cacheTTL       time.Duration
	nowFunc        func() time.Time

	mu    sync.Mutex
	cache map[string]jwksEntry // keyed by issuer URL
}

type jwksEntry struct {
	keys      []jwksKey
	fetchedAt time.Time
}

// OIDCOption configures an OIDCIssuerVerifier.
type OIDCOption func(*OIDCIssuerVerifier)

// WithHTTPClient sets the HTTP client used for JWKS fetches.
func WithHTTPClient(c *http.Client) OIDCOption {
	return func(v *OIDCIssuerVerifier) { v.httpClient = c }
}

// WithJWKSCacheTTL sets how long a fetched JWKS is cached before re-fetching.
// Default is 5 minutes.
func WithJWKSCacheTTL(d time.Duration) OIDCOption {
	return func(v *OIDCIssuerVerifier) { v.cacheTTL = d }
}

// NewOIDCIssuerVerifier creates an OIDCIssuerVerifier that accepts JWTs from
// any issuer in allowedIssuers. Pass an empty slice to reject all JWTs.
func NewOIDCIssuerVerifier(allowedIssuers []string, opts ...OIDCOption) *OIDCIssuerVerifier {
	allowed := make(map[string]struct{}, len(allowedIssuers))
	for _, iss := range allowedIssuers {
		allowed[iss] = struct{}{}
	}
	v := &OIDCIssuerVerifier{
		allowedIssuers: allowed,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		cacheTTL:       5 * time.Minute,
		nowFunc:        time.Now,
		cache:          make(map[string]jwksEntry),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyJWT validates the JWT signature using the issuer's JWKS and returns
// the full claims map on success.
func (v *OIDCIssuerVerifier) VerifyJWT(ctx context.Context, compactJWT string) (map[string]any, error) {
	// Parse without verification first to extract iss and kid.
	unverified, _, err := jwt.NewParser().ParseUnverified(compactJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	iss, err := unverified.Claims.GetIssuer()
	if err != nil || iss == "" {
		return nil, fmt.Errorf("JWT missing required 'iss' claim")
	}

	if _, ok := v.allowedIssuers[iss]; !ok {
		return nil, fmt.Errorf("JWT issuer %q is not in the allowed issuers list", iss)
	}

	keys, err := v.jwksKeys(ctx, iss)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS for issuer %q: %w", iss, err)
	}

	// kid from the JWT header selects which key to try first.
	kid, _ := unverified.Header["kid"].(string)

	key, err := selectKey(keys, kid)
	if err != nil {
		return nil, fmt.Errorf("no suitable key found in JWKS for issuer %q: %w", iss, err)
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(compactJWT, claims, func(_ *jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	return map[string]any(claims), nil
}

// jwksKeys returns cached or freshly fetched public keys for the issuer.
func (v *OIDCIssuerVerifier) jwksKeys(ctx context.Context, issuer string) ([]jwksKey, error) {
	v.mu.Lock()
	entry, ok := v.cache[issuer]
	if ok && v.nowFunc().Sub(entry.fetchedAt) < v.cacheTTL {
		v.mu.Unlock()
		return entry.keys, nil
	}
	v.mu.Unlock()

	keys, err := v.fetchJWKS(ctx, issuer)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	v.cache[issuer] = jwksEntry{keys: keys, fetchedAt: v.nowFunc()}
	v.mu.Unlock()

	return keys, nil
}

// fetchJWKS fetches {issuer}/.well-known/jwks.json and parses all public keys.
func (v *OIDCIssuerVerifier) fetchJWKS(ctx context.Context, issuer string) ([]jwksKey, error) {
	url := issuer + "/.well-known/jwks.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build JWKS request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	return parseJWKS(body)
}

// jwkSet is the JSON structure of a JWKS response.
type jwkSet struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwksKey struct {
	kid string
	pub crypto.PublicKey
}

// parseJWKS parses a JWKS JSON body and returns all usable public keys with
// their kid values.
func parseJWKS(body []byte) ([]jwksKey, error) {
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no keys")
	}

	var keys []jwksKey
	for _, raw := range set.Keys {
		jwk, err := keyutil.ReadJWK(raw)
		if err != nil {
			// Skip unsupported key types rather than failing entirely.
			continue
		}
		pub, err := jwk.PublicKey()
		if err != nil {
			continue
		}
		keys = append(keys, jwksKey{kid: jwk.KeyID, pub: pub})
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contained no usable public keys")
	}
	return keys, nil
}

// selectKey picks the key matching kid. If kid is empty or no key matches,
// the first key is returned (single-key JWKS are common).
func selectKey(keys []jwksKey, kid string) (crypto.PublicKey, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("empty key set")
	}
	if kid != "" {
		for _, k := range keys {
			if k.kid == kid {
				return k.pub, nil
			}
		}
		return nil, fmt.Errorf("no key with kid %q found in JWKS", kid)
	}
	return keys[0].pub, nil
}
