package sigkeydraft_test

import (
	"net/http"
	"testing"

	httpsig "github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/key"
	sigkey "github.com/remitly-oss/httpsig-go/sigkeydraft"
)

// TestSignatureKeyRoundTrip signs a request then verifies it using
// SignatureKeyFetcher, exercising the full sign→verify pipeline.
func TestSignatureKeyRoundTrip(t *testing.T) {
	srv := newSigkeyServer(t)

	jwkMap, signingPriv := ecJWKMap(t)

	claims := srv.standardClaims("alice")
	claims["cnf"] = map[string]any{"jwk": jwkMap}
	compactJWT := srv.signJWT(t, claims)

	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}

	profile := httpsig.SigningProfile{
		Algorithm: httpsig.Algo_ECDSA_P256_SHA256,
		Fields:    httpsig.Fields("@method", "@target-uri"),
		Metadata:  []httpsig.Metadata{httpsig.MetaCreated},
		Label:     "sig1",
	}
	if err := httpsig.Sign(req, profile, httpsig.SigningKey{Key: signingPriv}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	req.Header.Set("Signature-Key", makeSignatureKeyHeader("sig1", compactJWT))

	fetcher := sigkey.NewSignatureKeyFetcher("sig1", sigkey.NewOIDCIssuerVerifier([]string{srv.issuer()}))
	vp := httpsig.VerifyProfile{
		SignatureLabel:         "sig1",
		RequiredFields:         httpsig.Fields("@method", "@target-uri"),
		RequiredMetadata:       []httpsig.Metadata{httpsig.MetaCreated},
		AllowedAlgorithms:      []httpsig.Algorithm{httpsig.Algo_ECDSA_P256_SHA256},
		DisableTimeEnforcement: true,
	}

	result, err := httpsig.Verify(req, fetcher, vp)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected Verified=true")
	}

	spec, err := result.KeySpecer.KeySpec()
	if err != nil {
		t.Fatalf("KeySpec: %v", err)
	}
	if spec.Identity.Issuer != srv.issuer() {
		t.Errorf("Issuer: got %q, want %q", spec.Identity.Issuer, srv.issuer())
	}
	if spec.Identity.Identity != "alice" {
		t.Errorf("Identity: got %q, want %q", spec.Identity.Identity, "alice")
	}
	if spec.Identity.IssuerType != key.IssuerIDP {
		t.Errorf("IssuerType: got %q, want %q", spec.Identity.IssuerType, key.IssuerIDP)
	}
}
