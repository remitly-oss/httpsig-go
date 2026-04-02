// Package key defines the key specification types used for HTTP signature
// verification.
package key

import (
	"context"
	"crypto"
	"net/http"

	"github.com/remitly-oss/httpsig-go/types"
)

// IssuerType categorises the authority that vouches for a key's identity.
type IssuerType string

const (
	IssuerSelf   IssuerType = "self" // Public key provided without a third-party identity. See 'hwk' in Signature-Key spec.
	IssuerIDP    IssuerType = "idp"  // Identity Provider domain name. See 'jwt' and 'jwks_uri' in Signature-Key spec.
	IssuerCARoot IssuerType = "ca"   // CA root thumbprint.
)

// KeyIdentity carries the verified identity associated with a key.
type KeyIdentity struct {
	Identity   string
	IssuerType IssuerType
	Issuer     string
}

// KeySpec is the per-key information needed to verify a signature.
type KeySpec struct {
	KeyID    string
	Identity KeyIdentity // Optional. The key may be associated with an identity.
	Algo     types.Algorithm
	PubKey   crypto.PublicKey
	Secret   []byte // Shared secret for symmetric algorithms.
}

// KeySpec implements KeySpecer.
func (ks KeySpec) KeySpec() (KeySpec, error) {
	return ks, nil
}

// KeySpecer should be implemented by your key/credential store.
type KeySpecer interface {
	KeySpec() (KeySpec, error)
}


// KeyFetcher resolves a KeySpec for each incoming signature.
type KeyFetcher interface {
	// FetchByKeyID looks up a KeySpec from the 'keyid' metadata parameter on
	// the signature.
	FetchByKeyID(ctx context.Context, rh http.Header, keyID string) (KeySpecer, error)
	// Fetch looks up a KeySpec when keyid is not present in the signature.
	Fetch(ctx context.Context, rh http.Header, md types.MetadataProvider) (KeySpecer, error)
}
