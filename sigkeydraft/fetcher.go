package sigkeydraft

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/remitly-oss/httpsig-go/key"
	"github.com/remitly-oss/httpsig-go/keyutil"
	"github.com/remitly-oss/httpsig-go/types"
)

// SignatureKeyFetcher implements key.KeyFetcher by resolving keys from the
// Signature-Key header using draft-hardt-httpbis-signature-key-02.
//
// Only the jwt scheme is supported. For each verified signature label the
// fetcher validates the JWT via OIDCIssuerVerifier, extracts the public key
// from the cnf.jwk claim, and returns a KeySpec whose Identity field is
// populated from the JWT iss and sub claims.
type SignatureKeyFetcher struct {
	label          string
	issuerVerifier *OIDCIssuerVerifier
}

// NewSignatureKeyFetcher creates a SignatureKeyFetcher for the given signature
// label. issuerVerifier verifies the JWT and fetches the issuer's JWKS.
func NewSignatureKeyFetcher(label string, issuerVerifier *OIDCIssuerVerifier) *SignatureKeyFetcher {
	return &SignatureKeyFetcher{
		label:          label,
		issuerVerifier: issuerVerifier,
	}
}

// FetchByKeyID implements key.KeyFetcher. The keyID from the signature
// metadata is ignored because the key material is carried in the
// Signature-Key header.
func (f *SignatureKeyFetcher) FetchByKeyID(ctx context.Context, headers http.Header, _ string) (key.KeySpecer, error) {
	return f.fetchFromHeader(ctx, headers)
}

// Fetch implements key.KeyFetcher.
func (f *SignatureKeyFetcher) Fetch(ctx context.Context, headers http.Header, _ types.MetadataProvider) (key.KeySpecer, error) {
	return f.fetchFromHeader(ctx, headers)
}

func (f *SignatureKeyFetcher) fetchFromHeader(ctx context.Context, headers http.Header) (key.KeySpecer, error) {
	headerValue := headers.Get(Header)
	if headerValue == "" {
		return nil, fmt.Errorf("sigkey: Signature-Key header is missing or empty (label %q)", f.label)
	}

	entries, err := ParseHeader(headerValue)
	if err != nil {
		return nil, fmt.Errorf("sigkey: failed to parse Signature-Key header: %w", err)
	}

	entry, ok := entries[f.label]
	if !ok {
		return nil, fmt.Errorf("sigkey: Signature-Key header has no entry for label %q", f.label)
	}

	if entry.Scheme != SchemeJWT {
		return nil, fmt.Errorf("sigkey: scheme %q for label %q is not supported; only %q is supported", entry.Scheme, f.label, SchemeJWT)
	}

	return f.resolveJWT(ctx, entry)
}

// resolveJWT validates the JWT, extracts cnf.jwk, and builds a KeySpec.
func (f *SignatureKeyFetcher) resolveJWT(ctx context.Context, entry SigKeyHeader) (key.KeySpec, error) {
	compactJWT, err := entry.JWT()
	if err != nil {
		return key.KeySpec{}, fmt.Errorf("sigkey: %w", err)
	}

	claims, err := f.issuerVerifier.VerifyJWT(ctx, compactJWT)
	if err != nil {
		return key.KeySpec{}, fmt.Errorf("sigkey: JWT validation failed: %w", err)
	}

	pubKey, algo, err := extractCNFKey(claims)
	if err != nil {
		return key.KeySpec{}, err
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)

	return key.KeySpec{
		Algo:   algo,
		PubKey: pubKey,
		Identity: key.KeyIdentity{
			Identity:   sub,
			Issuer:     iss,
			IssuerType: key.IssuerIDP,
		},
	}, nil
}

// extractCNFKey extracts the public key and algorithm from the cnf.jwk claim.
func extractCNFKey(claims map[string]any) (pubKey any, algo types.Algorithm, err error) {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("sigkey: JWT is missing required 'cnf' claim")
	}

	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return nil, "", fmt.Errorf("sigkey: JWT cnf claim is missing required 'jwk' member")
	}

	// Re-marshal to JSON so we can use keyutil.ReadJWK for parsing.
	jwkJSON, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, "", fmt.Errorf("sigkey: failed to marshal cnf.jwk to JSON: %w", err)
	}

	jwk, err := keyutil.ReadJWK(jwkJSON)
	if err != nil {
		return nil, "", fmt.Errorf("sigkey: failed to parse cnf.jwk: %w", err)
	}

	algo, err = algoFromJWK(jwk)
	if err != nil {
		return nil, "", fmt.Errorf("sigkey: failed to determine algorithm from cnf.jwk: %w", err)
	}

	pk, err := jwk.PublicKey()
	if err != nil {
		return nil, "", fmt.Errorf("sigkey: failed to extract public key from cnf.jwk: %w", err)
	}

	return pk, algo, nil
}

// algoFromJWK infers the Algorithm from the public key extracted from the JWK.
// The spec requires that 'alg' MUST NOT be present in the JWK, so we derive
// the algorithm from the concrete key type and curve.
func algoFromJWK(j keyutil.JWK) (types.Algorithm, error) {
	pub, err := j.PublicKey()
	if err != nil {
		return "", fmt.Errorf("sigkey: cannot extract public key from JWK: %w", err)
	}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve.Params().Name {
		case "P-256":
			return types.Algo_ECDSA_P256_SHA256, nil
		case "P-384":
			return types.Algo_ECDSA_P384_SHA384, nil
		default:
			return "", fmt.Errorf("sigkey: unsupported EC curve %q", key.Curve.Params().Name)
		}
	default:
		return "", fmt.Errorf("sigkey: unsupported JWK key type %T", pub)
	}
}
