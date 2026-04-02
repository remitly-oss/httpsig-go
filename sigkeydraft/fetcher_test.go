package sigkeydraft_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/remitly-oss/httpsig-go/key"
	sigkey "github.com/remitly-oss/httpsig-go/sigkeydraft"
	"github.com/remitly-oss/httpsig-go/types"
)

// sigkeyServer is a test OIDC-like server that serves a JWKS and lets tests
// build signed JWTs against its key.
type sigkeyServer struct {
	priv   *ecdsa.PrivateKey
	server *httptest.Server
}

func newSigkeyServer(t *testing.T) *sigkeyServer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &sigkeyServer{priv: priv}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.jwksJSON(t))
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *sigkeyServer) issuer() string { return s.server.URL }

func (s *sigkeyServer) jwksJSON(t *testing.T) []byte {
	t.Helper()
	pub := &s.priv.PublicKey
	xPadded := padTo(pub.X.Bytes(), 32)
	yPadded := padTo(pub.Y.Bytes(), 32)
	type jwkJSON struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	b, err := json.Marshal(struct {
		Keys []jwkJSON `json:"keys"`
	}{Keys: []jwkJSON{{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(xPadded),
		Y: base64.RawURLEncoding.EncodeToString(yPadded),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *sigkeyServer) signJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(s.priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (s *sigkeyServer) standardClaims(sub string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": s.issuer(),
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
}

func padTo(b []byte, n int) []byte {
	padded := make([]byte, n)
	copy(padded[n-len(b):], b)
	return padded
}

func ecJWKMap(t *testing.T) (map[string]any, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padTo(pub.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padTo(pub.Y.Bytes(), 32)),
	}, priv
}

func ed25519JWKMap(t *testing.T) (map[string]any, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}, priv
}

func makeSignatureKeyHeader(label, compactJWT string) string {
	return label + `=jwt;jwt="` + compactJWT + `"`
}

func TestSignatureKeyFetcherJWT_EC(t *testing.T) {
	srv := newSigkeyServer(t)
	jwkMap, signingKey := ecJWKMap(t)

	claims := srv.standardClaims("alice")
	claims["cnf"] = map[string]any{"jwk": jwkMap}
	compactJWT := srv.signJWT(t, claims)

	headers := http.Header{}
	headers.Set("Signature-Key", makeSignatureKeyHeader("sig1", compactJWT))

	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{srv.issuer()}))

	ks, err := fetcher.FetchByKeyID(context.Background(), headers, "some-key-id")
	if err != nil {
		t.Fatalf("FetchByKeyID: %v", err)
	}
	spec, err := ks.KeySpec()
	if err != nil {
		t.Fatalf("KeySpec: %v", err)
	}

	if spec.Algo != types.Algo_ECDSA_P256_SHA256 {
		t.Errorf("Algo: got %q, want %q", spec.Algo, types.Algo_ECDSA_P256_SHA256)
	}
	ecPub, ok := spec.PubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PubKey type: got %T, want *ecdsa.PublicKey", spec.PubKey)
	}
	if ecPub.X.Cmp(signingKey.PublicKey.X) != 0 || ecPub.Y.Cmp(signingKey.PublicKey.Y) != 0 {
		t.Error("extracted public key does not match expected")
	}
	if spec.Identity.IssuerType != key.IssuerIDP {
		t.Errorf("IssuerType: got %q, want %q", spec.Identity.IssuerType, key.IssuerIDP)
	}
	if spec.Identity.Issuer != srv.issuer() {
		t.Errorf("Issuer: got %q, want %q", spec.Identity.Issuer, srv.issuer())
	}
	if spec.Identity.Identity != "alice" {
		t.Errorf("Identity (sub): got %q, want %q", spec.Identity.Identity, "alice")
	}
}

func TestSignatureKeyFetcherJWT_Ed25519(t *testing.T) {
	t.Skip("Ed25519/OKP JWK parsing not yet supported by keyutil")
	srv := newSigkeyServer(t)
	jwkMap, signingKey := ed25519JWKMap(t)

	claims := srv.standardClaims("bob")
	claims["cnf"] = map[string]any{"jwk": jwkMap}
	compactJWT := srv.signJWT(t, claims)

	headers := http.Header{}
	headers.Set("Signature-Key", makeSignatureKeyHeader("sig1", compactJWT))

	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{srv.issuer()}))

	ks, err := fetcher.Fetch(context.Background(), headers, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	spec, err := ks.KeySpec()
	if err != nil {
		t.Fatalf("KeySpec: %v", err)
	}

	if spec.Algo != types.Algo_ED25519 {
		t.Errorf("Algo: got %q, want %q", spec.Algo, types.Algo_ED25519)
	}
	edPub, ok := spec.PubKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PubKey type: got %T, want ed25519.PublicKey", spec.PubKey)
	}
	if string(edPub) != string(signingKey.Public().(ed25519.PublicKey)) {
		t.Error("extracted Ed25519 public key does not match expected")
	}
	if spec.Identity.Identity != "bob" {
		t.Errorf("Identity (sub): got %q, want %q", spec.Identity.Identity, "bob")
	}
}

func TestSignatureKeyFetcherMissingHeader(t *testing.T) {
	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{"https://idp.example.com"}))
	headers := http.Header{}

	_, err := fetcher.FetchByKeyID(context.Background(), headers, "key1")
	if err == nil {
		t.Fatal("expected error for missing Signature-Key header")
	}
}

func TestSignatureKeyFetcherMissingLabel(t *testing.T) {
	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{"https://idp.example.com"}))
	headers := http.Header{}
	headers.Set("Signature-Key", `other=jwt;jwt="tok"`)

	_, err := fetcher.FetchByKeyID(context.Background(), headers, "key1")
	if err == nil {
		t.Fatal("expected error for missing label")
	}
}

func TestSignatureKeyFetcherUnsupportedScheme(t *testing.T) {
	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{"https://idp.example.com"}))
	headers := http.Header{}
	headers.Set("Signature-Key", `sig1=hwk;kty="EC";crv="P-256";x="abc";y="def"`)

	_, err := fetcher.FetchByKeyID(context.Background(), headers, "key1")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestSignatureKeyFetcherJWTVerificationError(t *testing.T) {
	srv := newSigkeyServer(t)

	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := srv.standardClaims("alice")
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	compactJWT, err := tok.SignedString(otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	headers := http.Header{}
	headers.Set("Signature-Key", makeSignatureKeyHeader("sig1", compactJWT))

	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{srv.issuer()}))

	_, err = fetcher.FetchByKeyID(context.Background(), headers, "key1")
	if err == nil {
		t.Fatal("expected error for JWT verification failure")
	}
}

func TestSignatureKeyFetcherMissingCNF(t *testing.T) {
	srv := newSigkeyServer(t)

	claims := srv.standardClaims("alice")
	compactJWT := srv.signJWT(t, claims)

	headers := http.Header{}
	headers.Set("Signature-Key", makeSignatureKeyHeader("sig1", compactJWT))

	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{srv.issuer()}))

	_, err := fetcher.FetchByKeyID(context.Background(), headers, "key1")
	if err == nil {
		t.Fatal("expected error for missing cnf claim")
	}
}

func TestSignatureKeyFetcherMissingCNFJWK(t *testing.T) {
	srv := newSigkeyServer(t)

	claims := srv.standardClaims("alice")
	claims["cnf"] = map[string]any{"kid": "some-key"}
	compactJWT := srv.signJWT(t, claims)

	headers := http.Header{}
	headers.Set("Signature-Key", makeSignatureKeyHeader("sig1", compactJWT))

	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{srv.issuer()}))

	_, err := fetcher.FetchByKeyID(context.Background(), headers, "key1")
	if err == nil {
		t.Fatal("expected error for missing cnf.jwk")
	}
}
