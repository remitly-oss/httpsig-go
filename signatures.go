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
	"fmt"
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
}

func sign(hrr httpReqResp, sp sigParameters) error {
	base, err := calculateSignatureBase(hrr, sp.Base)
	if err != nil {
		return err
	}

	var sigBytes []byte
	switch sp.Algo {

	case Algo_RSA_PSS_SHA512:
		if rsapk, ok := sp.PrivateKey.(*rsa.PrivateKey); ok {
			msgHash := sha512.Sum512(base.base)
			opts := &rsa.PSSOptions{
				SaltLength: 64,
				Hash:       crypto.SHA512,
			}
			sigBytes, err = rsa.SignPSS(rand.Reader, rsapk, crypto.SHA512, msgHash[:], opts)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Invalid private key. Requires rsa.PrivateKey: %T", sp.PrivateKey)
		}
	case Algo_RSA_v1_5_sha256:
		if rsapk, ok := sp.PrivateKey.(*rsa.PrivateKey); ok {
			msgHash := sha256.Sum256(base.base)
			sigBytes, err = rsa.SignPKCS1v15(rand.Reader, rsapk, crypto.SHA256, msgHash[:])
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Invalid private key. Requires rsa.PrivateKey: %T", sp.PrivateKey)
		}
	case Algo_ECDSA_P256_SHA256:
		if eccpk, ok := sp.PrivateKey.(*ecdsa.PrivateKey); ok {
			msgHash := sha256.Sum256(base.base)
			sigBytes, err = ecdsa.SignASN1(rand.Reader, eccpk, msgHash[:])
			if err != nil {
				return newError(ErrVerification, "Failed to sign with ecdsa private key", err)
			}
		} else {
			return fmt.Errorf("Invalid private key. Requires ed25519.PrivateKey")
		}
	case Algo_ED25519:
		if edpk, ok := sp.PrivateKey.(ed25519.PrivateKey); ok {
			sigBytes = ed25519.Sign(edpk, base.base)
		} else {
			return fmt.Errorf("Invalid private key. Requires ed25519.PrivateKey")
		}
	case Algo_HMAC_SHA256:
		msgHash := hmac.New(sha256.New, sp.Secret)
		msgHash.Write(base.base) // write does not return an error per hash.Hash documentation
		sigBytes = msgHash.Sum(nil)
	default:
		return newError(ErrInvalidAlgorithm, fmt.Sprintf("Signing algorithm not supported: '%s'", sp.Algo))
	}
	sigField := sfv.NewDictionary()
	sigField.Add(sp.Label, sfv.NewItem(sigBytes))
	signature, err := sfv.Marshal(sigField)
	if err != nil {
		return newError(ErrInvalidAlgorithm, fmt.Sprintf("bad marshal - label; %s", sp.Label), err)
	}
	hrr.Headers().Set("Signature-Input", fmt.Sprintf("%s=%s", sp.Label, base.signatureInput))
	hrr.Headers().Set("Signature", signature)
	return nil
}

func timestamp(nowtime func() time.Time) int {
	return int(nowtime().Unix())
}

func genNonce() string {
	return ""
}
