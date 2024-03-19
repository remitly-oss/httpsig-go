package httpsig

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

const (
	// Hints for reading key
	PKCS1        string = "pkcs1"
	PKCS8        string = "pkcs8"
	PKCS8_RSAPSS string = "pkcs8_rsapss" // Go doesn't support
	PKIX         string = "pxix"
)

// ReadPublicKey decodes a PEM encoded public key and parses into crypto.PublicKey
func ReadPublicKey(encodedPubkey []byte, hint ...string) (crypto.PublicKey, error) {
	block, _ := pem.Decode(encodedPubkey)
	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode public key")
	}
	var key crypto.PublicKey
	var err error

	format := PKIX
	if len(hint) > 0 {
		format = hint[0]
	}
	switch format {
	case PKIX:
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse public key with PKIX: %w", err)
		}
	default:
		return nil, fmt.Errorf("Unsupported pubkey format '%s'", format)
	}

	return key, nil
}

// ReadPrivateKey decodes a PEM encoded private key and parses into a crypto.PrivateKey
func ReadPrivateKey(encodedPrivateKey []byte, hint ...string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(encodedPrivateKey)

	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode private key")
	}

	var key crypto.PrivateKey
	var err error

	format := PKCS8
	if len(hint) > 0 {
		format = hint[0]
	}
	switch format {
	case PKCS8:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse private key with PKCS8: %w", err)
		}
	case PKCS1:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse private key with PKCS1: %w", err)
		}
	case PKCS8_RSAPSS:
		// The rsa-pss key is PKCS8 encoded but the golang 1.12 parser doesn't recoganize the algorithm and gives 'PKCS#8 wrapping contained private key with unknown algorithm: 1.2.840.113549.1.1.10
		// This asn1 unmarshalls to avoid the OID check.
		pkcs8 := struct {
			Version    int
			Algo       pkix.AlgorithmIdentifier
			PrivateKey []byte
		}{}

		_, err := asn1.Unmarshal(block.Bytes, &pkcs8)
		if err != nil {
			return nil, fmt.Errorf("Failed to ans1 unmarshal private key: %w", err)
		}
		key, err = x509.ParsePKCS1PrivateKey(pkcs8.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse private key with PKCS1: %w", err)
		}
	default:
		return nil, fmt.Errorf("Unsupported private key format '%s'", format)
	}

	return key, nil
}
