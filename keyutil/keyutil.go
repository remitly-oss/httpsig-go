package keyutil

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

// Private or public key schema
type Format string

const (
	// Hints for reading key
	PKCS1        Format = "pkcs1"
	PKCS8        Format = "pkcs8"
	PKCS8_RSAPSS Format = "pkcs8_rsapss" // Go doesn't support
	PKIX         Format = "pxix"
	ECC          Format = "ecc"
)

var (
	oidPublicKeyRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

// MustReadPublicKeyFile reads a PEM encoded public key file or panics
func MustReadPublicKeyFile(pubkeyFile string, override ...Format) crypto.PublicKey {
	pk, err := ReadPublicKeyFile(pubkeyFile, override...)
	if err != nil {
		panic(err)
	}
	return pk
}

// ReadPublicKeyFile reads a PEM encdoded public key file and parses into crypto.PublicKey
func ReadPublicKeyFile(pubkeyFile string, override ...Format) (crypto.PublicKey, error) {
	keyBytes, err := os.ReadFile(pubkeyFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key file '%s': %w", pubkeyFile, err)
	}
	return ReadPublicKey(keyBytes, override...)
}

// ReadPublicKey decodes a PEM encoded public key and parses into crypto.PublicKey
func ReadPublicKey(encodedPubkey []byte, override ...Format) (crypto.PublicKey, error) {
	block, _ := pem.Decode(encodedPubkey)
	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode public key")
	}
	var key crypto.PublicKey
	var err error

	format := PKIX
	if len(override) > 0 {
		format = override[0]
	}
	switch format {
	case PKIX:
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case PKCS1:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("Unsupported pubkey format '%s'", format)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key with format '%s': %w", format, err)
	}

	return key, nil
}

// MustReadPrivateKeyFile decodes a PEM encoded private key file and parses into a crypto.PrivateKey or panics.
func MustReadPrivateKeyFile(pkFile string, override ...Format) crypto.PrivateKey {
	pk, err := ReadPrivateKeyFile(pkFile, override...)
	if err != nil {
		panic(err)
	}
	return pk
}

// ReadPrivateKeyFile decodes a PEM encoded private key file and parses into a crypto.PrivateKey
func ReadPrivateKeyFile(pkFile string, override ...Format) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(pkFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private key file '%s': %w", pkFile, err)
	}
	return ReadPrivateKey(keyBytes, override...)
}

func ReadPrivateKey(encodedPrivateKey []byte, override ...Format) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(encodedPrivateKey)

	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode private key")
	}

	var key crypto.PrivateKey
	var err error

	format := PKCS8 // PCKS8 handles all support algorithms. However older keys may be encoded in another format.
	if len(override) > 0 {
		format = override[0]
	}
	switch format {
	case PKCS8, PKCS8_RSAPSS:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try to handle RSAPSS
			psskey, psserr := parseRSAPSS(block)
			if psserr == nil {
				// success
				key = psskey
				err = psserr
			}
		}
	case PKCS1:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case ECC:
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("Unsupported private key format '%s'", format)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key with format '%s': %w", format, err)
	}
	return key, nil
}

func parseRSAPSS(block *pem.Block) (crypto.PrivateKey, error) {
	// The rsa-pss key is PKCS8 encoded but the golang 1.19 parser doesn't recognize the algorithm and gives 'PKCS#8 wrapping contained private key with unknown algorithm: 1.2.840.113549.1.1.10

	// Instead do the asn1 unmarshaling and check here.
	pkcs8 := struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{}

	_, err := asn1.Unmarshal(block.Bytes, &pkcs8)
	if err != nil {
		return nil, fmt.Errorf("Failed to ans1 unmarshal private key: %w", err)
	}

	if !pkcs8.Algo.Algorithm.Equal(oidPublicKeyRSAPSS) {
		return nil, fmt.Errorf("PKCS#8 wrapping contained private key with unknown algorithm: %s", pkcs8.Algo.Algorithm)
	}
	return x509.ParsePKCS1PrivateKey(pkcs8.PrivateKey)
}
