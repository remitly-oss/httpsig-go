package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	sfv "github.com/dunglas/httpsfv"
)

// derived component names
type derived string

const (
	sigparams derived = "@signature-params"
	method    derived = "@method"
	path      derived = "@path"
	targetURI derived = "@target-uri"
	authority derived = "@authority"
)

// MetadataProvider allows customized functions for metadata parameter values. Not needed for default usage.
type MetadataProvider interface {
	Created() (int, error)
	Expires() (int, error)
	Nonce() (string, error)
	Alg() (string, error)
	KeyID() (string, error)
	Tag() (string, error)
}

type signatureBase struct {
	base           []byte // The full signature base. Use this as input to signing and verification
	signatureInput string // The signature-input line
}

type sigParameters struct {
	Base       sigBaseInput
	Algo       Algorithm
	Label      string
	PrivateKey crypto.PrivateKey
	Secret     []byte
	Opts       SigningKeyOpts
}

func sign(hrr httpMessage, sp sigParameters) error {
	base, err := calculateSignatureBase(hrr, sp.Base)
	if err != nil {
		return err
	}

	var sigBytes []byte
	pkSigner := sp.Opts.Signer // Use crypto.Signer interface if set.

	// Use the crypto.Signer generic `Sign` method if crypto.Signer is provided in the SigningKeyOpts
	// If crypto.PrivateKey is provided do a type check that the PrivateKey type matches the signing algorithm.
	switch sp.Algo {
	case Algo_RSA_PSS_SHA512:
		if pkSigner == nil {
			if rsapk, ok := sp.PrivateKey.(*rsa.PrivateKey); ok {
				pkSigner = rsapk
			} else {
				return fmt.Errorf("Invalid private key. Requires *rsa.PrivateKey: %T", sp.PrivateKey)
			}
		}

		msgHash := sha512.Sum512(base.base)
		opts := &rsa.PSSOptions{
			SaltLength: 64,
			Hash:       crypto.SHA512,
		}
		sigBytes, err = pkSigner.Sign(rand.Reader, msgHash[:], opts)
		if err != nil {
			return newError(ErrInternal, "Failed to sign RSA PSS", err)
		}
	case Algo_RSA_v1_5_sha256:
		if pkSigner == nil {
			if rsapk, ok := sp.PrivateKey.(*rsa.PrivateKey); ok {
				pkSigner = rsapk
			} else {
				return fmt.Errorf("Invalid private key. Requires *rsa.PrivateKey: %T", sp.PrivateKey)
			}
		}
		msgHash := sha256.Sum256(base.base)
		sigBytes, err = pkSigner.Sign(rand.Reader, msgHash[:], crypto.SHA256)
		if err != nil {
			return newError(ErrInternal, "Failed to sign RSA v1.5", err)
		}
	case Algo_ECDSA_P256_SHA256:
		msgHash := sha256.Sum256(base.base)
		if pkSigner == nil {
			if eccpk, ok := sp.PrivateKey.(*ecdsa.PrivateKey); ok {
				// Use the native ecdsa.Sign method to avoid needing to decode ASN.1 result.
				r, s, err := ecdsa.Sign(rand.Reader, eccpk, msgHash[:])
				if err != nil {
					return newError(ErrInternal, "Failed to sign with ecdsa private key", err)
				}
				// Concatenate r and s to make the signature as per the spec. r and s are *not* encoded in ASN1 format
				sigBytes = ecdsaConcatRS(r, s, 64)
			} else {
				return fmt.Errorf("Invalid private key. Requires *ecdsa.PrivateKey")
			}
		} else {
			// crypto.Signer for ECDSA may return the signature in ASN.1 format
			sigBytes, err = pkSigner.Sign(rand.Reader, msgHash[:], crypto.SHA256)
			if err != nil {
				return newError(ErrInternal, "Failed to sign with ecdsa private key", err)
			}
			sigBytes, err = sp.ecdsaHandleASN1(sigBytes, err, 64)
		}
	case Algo_ECDSA_P384_SHA384:
		msgHash := sha512.Sum384(base.base)
		if pkSigner == nil {
			if eccpk, ok := sp.PrivateKey.(*ecdsa.PrivateKey); ok {
				r, s, err := ecdsa.Sign(rand.Reader, eccpk, msgHash[:])
				if err != nil {
					return newError(ErrInternal, "Failed to sign with ecdsa private key", err)
				}
				// Concatenate r and s to make the signature as per the spec. r and s are *not* encoded in ASN1 format
				sigBytes = ecdsaConcatRS(r, s, 96)
			} else {
				return fmt.Errorf("Invalid private key. Requires *ecdsa.PrivateKey")
			}
		} else {
			// crypto.Signer for ECDSA may return the signature in ASN.1 format
			sigBytes, err = pkSigner.Sign(rand.Reader, msgHash[:], crypto.SHA384)
			if err != nil {
				return newError(ErrInternal, "Failed to sign with ecdsa private key", err)
			}
			sigBytes, err = sp.ecdsaHandleASN1(sigBytes, err, 96)
		}
	case Algo_ED25519:
		if pkSigner == nil {
			if edpk, ok := sp.PrivateKey.(ed25519.PrivateKey); ok {
				sigBytes = ed25519.Sign(edpk, base.base)
			} else {
				return fmt.Errorf("Invalid private key. Requires ed25519.PrivateKey")
			}
		} else {
			// No prehash function per the spec.
			sigBytes, err = pkSigner.Sign(nil, base.base, crypto.Hash(0))
		}
	case Algo_HMAC_SHA256:
		if len(sp.Secret) == 0 {
			return newError(ErrInvalidSignatureOptions, fmt.Sprintf("No secret provided for symmetric algorithm '%s'", Algo_HMAC_SHA256))
		}
		msgHash := hmac.New(sha256.New, sp.Secret)
		msgHash.Write(base.base) // write does not return an error per hash.Hash documentation
		sigBytes = msgHash.Sum(nil)
	default:
		return newError(ErrInvalidSignatureOptions, fmt.Sprintf("Signing algorithm not supported: '%s'", sp.Algo))
	}
	sigField := sfv.NewDictionary()
	sigField.Add(sp.Label, sfv.NewItem(sigBytes))
	signature, err := sfv.Marshal(sigField)
	if err != nil {
		return newError(ErrInternal, fmt.Sprintf("Failed to marshal signature for label '%s'", sp.Label), err)
	}
	hrr.Headers().Set("Signature-Input", fmt.Sprintf("%s=%s", sp.Label, base.signatureInput))
	hrr.Headers().Set("Signature", signature)
	return nil
}

// ecdsaHandleASN1 is intended to wrap a call to crypto.Signer.Sign for ECDSA algorithms like this: sp.ecdsaHandleASN1(crSigner.Sign(rnad.Reader, msgHash, crypto.SHA256). Some implementations may return an ASN.1 formatted signature but the HTTP Signatures spec and other implementations use a concatenated R | S format.
func (sp sigParameters) ecdsaHandleASN1(sig []byte, sigerr error, sigsize int) ([]byte, error) {
	if !sp.Opts.ASN1ForECDSA {
		return sig, sigerr
	}
	// HTTP Signatures spec uses R|S concat instead of ASN.1. Have to decode the crypto.Sign result.
	encSig := struct {
		R, S *big.Int
	}{}
	if _, err := asn1.Unmarshal(sig, &encSig); err != nil {
		return sig, newError(ErrInternal, "Failed to sign with ecdsa private key. Sign did not return ASN.1 signature", err)
	}
	return ecdsaConcatRS(encSig.R, encSig.S, sigsize), nil
}

func ecdsaConcatRS(r, s *big.Int, signatureSize int) []byte {
	half := signatureSize / 2
	sigBytes := make([]byte, signatureSize)
	r.FillBytes(sigBytes[0:half])
	s.FillBytes(sigBytes[half:signatureSize])
	return sigBytes
}

func timestamp(nowtime func() time.Time) int {
	return int(nowtime().Unix())
}
