package sigkeydraft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// buildJWKSResponse builds a minimal JWKS JSON body from an ECDSA public key.
func buildJWKSResponse(t *testing.T, pub *ecdsa.PublicKey, kid string) []byte {
	t.Helper()
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	type jwkJSON struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid,omitempty"`
	}
	set := struct {
		Keys []jwkJSON `json:"keys"`
	}{
		Keys: []jwkJSON{{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xPadded),
			Y:   base64.RawURLEncoding.EncodeToString(yPadded),
			Kid: kid,
		}},
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildSignedJWT builds a compact JWT signed with the given ECDSA private key.
func buildSignedJWT(t *testing.T, priv *ecdsa.PrivateKey, issuer, subject, kid string, extra map[string]any) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestOIDCIssuerVerifier_Valid(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksBody := buildJWKSResponse(t, &priv.PublicKey, "key1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	}))
	defer server.Close()

	issuer := server.URL
	compactJWT := buildSignedJWT(t, priv, issuer, "alice", "key1", nil)

	v := NewOIDCIssuerVerifier([]string{issuer})
	claims, err := v.VerifyJWT(context.Background(), compactJWT)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub: got %v, want %q", claims["sub"], "alice")
	}
	if claims["iss"] != issuer {
		t.Errorf("iss: got %v, want %q", claims["iss"], issuer)
	}
}

func TestOIDCIssuerVerifier_DisallowedIssuer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compactJWT := buildSignedJWT(t, priv, "https://untrusted.example.com", "alice", "", nil)

	v := NewOIDCIssuerVerifier([]string{"https://trusted.example.com"})
	_, err = v.VerifyJWT(context.Background(), compactJWT)
	if err == nil {
		t.Fatal("expected error for disallowed issuer")
	}
}

func TestOIDCIssuerVerifier_ExpiredJWT(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksBody := buildJWKSResponse(t, &priv.PublicKey, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwksBody)
	}))
	defer server.Close()

	issuer := server.URL
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "alice",
		"iat": time.Now().Add(-10 * time.Minute).Unix(),
		"exp": time.Now().Add(-5 * time.Minute).Unix(), // already expired
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	compactJWT, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	v := NewOIDCIssuerVerifier([]string{issuer})
	_, err = v.VerifyJWT(context.Background(), compactJWT)
	if err == nil {
		t.Fatal("expected error for expired JWT")
	}
}

func TestOIDCIssuerVerifier_WrongKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// JWKS has otherPriv's public key, but JWT is signed with priv.
	jwksBody := buildJWKSResponse(t, &otherPriv.PublicKey, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwksBody)
	}))
	defer server.Close()

	issuer := server.URL
	compactJWT := buildSignedJWT(t, priv, issuer, "alice", "", nil)

	v := NewOIDCIssuerVerifier([]string{issuer})
	_, err = v.VerifyJWT(context.Background(), compactJWT)
	if err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestOIDCIssuerVerifier_JWKSCached(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fetchCount := 0
	jwksBody := buildJWKSResponse(t, &priv.PublicKey, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(jwksBody)
	}))
	defer server.Close()

	issuer := server.URL
	v := NewOIDCIssuerVerifier([]string{issuer}, WithJWKSCacheTTL(time.Minute))

	for i := 0; i < 3; i++ {
		compactJWT := buildSignedJWT(t, priv, issuer, "alice", "", nil)
		if _, err := v.VerifyJWT(context.Background(), compactJWT); err != nil {
			t.Fatalf("VerifyJWT call %d: %v", i, err)
		}
	}

	if fetchCount != 1 {
		t.Errorf("JWKS fetched %d times, want 1 (should be cached)", fetchCount)
	}
}

func TestOIDCIssuerVerifier_JWKSCacheExpiry(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fetchCount := 0
	jwksBody := buildJWKSResponse(t, &priv.PublicKey, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(jwksBody)
	}))
	defer server.Close()

	issuer := server.URL

	now := time.Now()
	v := NewOIDCIssuerVerifier([]string{issuer}, WithJWKSCacheTTL(time.Minute))
	v.nowFunc = func() time.Time { return now }

	compactJWT := buildSignedJWT(t, priv, issuer, "alice", "", nil)
	if _, err := v.VerifyJWT(context.Background(), compactJWT); err != nil {
		t.Fatalf("first VerifyJWT: %v", err)
	}

	// Advance time past TTL.
	v.nowFunc = func() time.Time { return now.Add(2 * time.Minute) }

	compactJWT = buildSignedJWT(t, priv, issuer, "alice", "", nil)
	if _, err := v.VerifyJWT(context.Background(), compactJWT); err != nil {
		t.Fatalf("second VerifyJWT: %v", err)
	}

	if fetchCount != 2 {
		t.Errorf("JWKS fetched %d times, want 2 (cache should have expired)", fetchCount)
	}
}

func TestOIDCIssuerVerifier_KidSelection(t *testing.T) {
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// JWKS with two keys; JWT uses kid "key2".
	xBytes1 := priv1.PublicKey.X.Bytes()
	yBytes1 := priv1.PublicKey.Y.Bytes()
	xPadded1 := make([]byte, 32)
	yPadded1 := make([]byte, 32)
	copy(xPadded1[32-len(xBytes1):], xBytes1)
	copy(yPadded1[32-len(yBytes1):], yBytes1)

	xBytes2 := priv2.PublicKey.X.Bytes()
	yBytes2 := priv2.PublicKey.Y.Bytes()
	xPadded2 := make([]byte, 32)
	yPadded2 := make([]byte, 32)
	copy(xPadded2[32-len(xBytes2):], xBytes2)
	copy(yPadded2[32-len(yBytes2):], yBytes2)

	type jwkJSON struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid"`
	}
	set := struct {
		Keys []jwkJSON `json:"keys"`
	}{Keys: []jwkJSON{
		{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(xPadded1), Y: base64.RawURLEncoding.EncodeToString(yPadded1), Kid: "key1"},
		{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(xPadded2), Y: base64.RawURLEncoding.EncodeToString(yPadded2), Kid: "key2"},
	}}
	jwksBody, _ := json.Marshal(set)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwksBody)
	}))
	defer server.Close()

	issuer := server.URL
	// Sign with priv2, kid="key2" — verifier must select key2 not key1.
	compactJWT := buildSignedJWT(t, priv2, issuer, "bob", "key2", nil)

	v := NewOIDCIssuerVerifier([]string{issuer})
	claims, err := v.VerifyJWT(context.Background(), compactJWT)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims["sub"] != "bob" {
		t.Errorf("sub: got %v, want %q", claims["sub"], "bob")
	}
}
