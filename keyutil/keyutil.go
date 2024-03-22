package keyutil

import (
	"crypto"
	"fmt"
	"net/http"
	"os"

	"github.com/remitly-oss/httpsig-go"
)

const (
	// Hints for reading key
	PKCS1        string = "pkcs1"
	PKCS8        string = "pkcs8"
	PKCS8_RSAPSS string = "pkcs8_rsapss" // Go doesn't support
	PKIX         string = "pxix"
	ECC          string = "ecc"
)

// MustReadPublicKeyFile reads a PEM encoded public key file or panics
func MustReadPublicKeyFile(pubkeyFile string, hint ...string) crypto.PublicKey {
	pk, err := ReadPublicKeyFile(pubkeyFile, hint...)
	if err != nil {
		panic(err)
	}
	return pk
}

// ReadPublicKeyFile reads a PEM encdoded public key file and parses into crypto.PublicKey
func ReadPublicKeyFile(pubkeyFile string, hint ...string) (crypto.PublicKey, error) {
	keyBytes, err := os.ReadFile(pubkeyFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key file '%s': %w", pubkeyFile, err)
	}
	return ReadPublicKey(keyBytes, hint...)
}

// ReadPublicKey decodes a PEM encoded public key and parses into crypto.PublicKey
func ReadPublicKey(encodedPubkey []byte, hint ...string) (crypto.PublicKey, error) {
	return httpsig.ReadPublicKey(encodedPubkey, hint...)
}

// MustReadPrivateKeyFile decodes a PEM encoded private key file and parses into a crypto.PrivateKey or panics.
func MustReadPrivateKeyFile(pkFile string, hint ...string) crypto.PrivateKey {
	pk, err := ReadPrivateKeyFile(pkFile, hint...)
	if err != nil {
		panic(err)
	}
	return pk
}

// ReadPrivateKeyFile decodes a PEM encoded private key file and parses into a crypto.PrivateKey
func ReadPrivateKeyFile(pkFile string, hint ...string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(pkFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private key file '%s': %w", pkFile, err)
	}
	return httpsig.ReadPrivateKey(keyBytes, hint...)
}

func ReadPrivateKey(encodedPrivateKey []byte, hint ...string) (crypto.PrivateKey, error) {
	return httpsig.ReadPrivateKey(encodedPrivateKey, hint...)
}

// KeyFetchInMemory implements KeyFetcher for public keys stored in memory.
type KeyFetchInMemory struct {
	pubkeys map[string]httpsig.KeySpec
}

func NewKeyFetchInMemory(pubkeys map[string]httpsig.KeySpec) *KeyFetchInMemory {
	return &KeyFetchInMemory{pubkeys}
}

func (kf *KeyFetchInMemory) FetchByKeyID(keyID string) (httpsig.KeySpec, error) {
	ks, found := kf.pubkeys[keyID]
	if !found {
		return httpsig.KeySpec{}, fmt.Errorf("Key for keyid '%s' not found", keyID)
	}
	return ks, nil
}

func (kf *KeyFetchInMemory) Fetch(http.Header, httpsig.MetadataProvider) (httpsig.KeySpec, error) {
	return httpsig.KeySpec{}, fmt.Errorf("Fetch without keyid not supported")
}
