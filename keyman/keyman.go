// keyman provides key management functionality
package keyman

import (
	"context"
	"fmt"
	"net/http"

	"github.com/remitly-oss/httpsig-go"
)

// KeyFetchInMemory implements KeyFetcher for public keys stored in memory.
type KeyFetchInMemory struct {
	pubkeys map[string]httpsig.KeySpec
}

func NewKeyFetchInMemory(pubkeys map[string]httpsig.KeySpec) *KeyFetchInMemory {
	if pubkeys == nil {
		pubkeys = map[string]httpsig.KeySpec{}
	}
	return &KeyFetchInMemory{pubkeys}
}

func (kf *KeyFetchInMemory) FetchByKeyID(ctx context.Context, keyID string) (httpsig.KeySpec, error) {
	ks, found := kf.pubkeys[keyID]
	if !found {
		return httpsig.KeySpec{}, fmt.Errorf("Key for keyid '%s' not found", keyID)
	}
	return ks, nil
}

func (kf *KeyFetchInMemory) Fetch(context.Context, http.Header, httpsig.MetadataProvider) (httpsig.KeySpec, error) {
	return httpsig.KeySpec{}, fmt.Errorf("Fetch without keyid not supported")
}
