package keyutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

func ReadJWKFile(jwkFile string) (JWK, error) {
	keyBytes, err := os.ReadFile(jwkFile)
	if err != nil {
		return JWK{}, fmt.Errorf("Failed to read jwk key file '%s': %w", jwkFile, err)
	}
	return ReadJWK(keyBytes)
}

func ReadJWK(jwkBytes []byte) (JWK, error) {
	base := jwk{}
	err := json.Unmarshal(jwkBytes, &base)
	if err != nil {
		return JWK{}, fmt.Errorf("Failed to json parse JWK public key: %w", err)
	}
	return JWK{
		KeyType:   base.KeyType,
		Algorithm: base.Algo,
		KeyID:     base.KeyID,
		raw:       json.RawMessage(jwkBytes),
	}, nil
}

// ReadJWKFromPEM converts a PEM encoded private key to JWK
func ReadJWKFromPEM(pkeyBytes []byte) (JWK, error) {
	pkey, err := ReadPrivateKey(pkeyBytes)
	if err != nil {
		return JWK{}, err
	}
	return FromPrivateKey(pkey)
}

func FromPrivateKey(pkey crypto.PrivateKey) (JWK, error) {
	switch key := pkey.(type) {
	case *ecdsa.PrivateKey:
		jwk := jwkEC{
			Curve: key.Curve.Params().Name,
			X:     octet{key.X},
			Y:     octet{key.Y},
			D:     octet{key.D},
		}
		out, err := json.Marshal(jwk)
		if err != nil {
			return JWK{}, fmt.Errorf("Error marshalling JWK: %w", err)
		}
		return JWK{
			KeyType: "EC",
			raw:     out,
		}, nil
	default:
		return JWK{}, fmt.Errorf("Unsupported private key type '%T'", pkey)
	}
}

// JWK provides basic data and usage for a JWK.
type JWK struct {
	KeyType   string // 'kty'
	Algorithm string // 'alg'
	KeyID     string // 'kid'
	raw       json.RawMessage
}

func (ji *JWK) PublicKey() (crypto.PublicKey, error) {
	switch ji.KeyType {
	case "EC": // ECC
		jwk := jwkEC{}
		err := json.Unmarshal(ji.raw, &jwk)
		if err != nil {
			return JWK{}, fmt.Errorf("Failed to json parse JWK into key type 'EC': %w", err)
		}
		return jwk.PublicKey()
	}

	return nil, fmt.Errorf("Unsupported key type for PublicKey'%s'", ji.KeyType)
}

func (ji *JWK) PrivateKey() (crypto.PrivateKey, error) {
	switch ji.KeyType {
	case "EC":
		jwk := jwkEC{}
		err := json.Unmarshal(ji.raw, &jwk)
		if err != nil {
			return JWK{}, fmt.Errorf("Failed to json parse JWK into key type 'EC': %w", err)
		}
		return jwk.PrivateKey()
	}
	return nil, fmt.Errorf("Unsupported key type PrivateKey '%s'", ji.KeyType)
}

func (ji *JWK) SecretKey() ([]byte, error) {
	switch ji.KeyType {
	case "oct":
		jwk := jwkSymmetric{}
		err := json.Unmarshal(ji.raw, &jwk)
		if err != nil {
			return nil, fmt.Errorf("Failed to json parse JWK into key type 'oct': %w", err)
		}
		return jwk.Key(), nil
	}
	return nil, fmt.Errorf("Unsupported key type for Secret '%s'", ji.KeyType)
}

// octet represents the data for base64 URL encoded data as specified by JWKs.
type octet struct {
	*big.Int
}

func (ob octet) MarshalJSON() ([]byte, error) {
	out := fmt.Sprintf("\"%s\"", base64.RawURLEncoding.EncodeToString(ob.Bytes()))
	return []byte(out), nil
}

func (ob *octet) UnmarshalJSON(data []byte) error {
	// data is the json value and must be unmarshaled into a go string first
	encoded := ""
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	rawBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("Failed to base64 decode: %w", err)
	}

	x := new(big.Int)
	x.SetBytes(rawBytes)
	*ob = octet{x}

	return nil
}

type jwk struct {
	KeyType string `json:"kty"`           // kty  algorithm family used with the key such as "RSA" or "EC".
	Algo    string `json:"alg,omitempty"` // alg identifies the algorithm intended for use with the key.
	KeyID   string `json:"kid,omitempty"` // Used to match a specific key
}

type jwkEC struct {
	jwk
	Curve string `json:"crv"`         // The curve used with the key e.g. P-256
	X     octet  `json:"x"`           // x coordinate of the curve.
	Y     octet  `json:"y"`           // y coordinate of the curve.
	D     octet  `json:"d,omitempty"` // For private keys.
}

func (ec *jwkEC) params() (crv elliptic.Curve, byteLen int, e error) {
	switch ec.Curve {
	case "P-256":
		crv = elliptic.P256()
	case "P-384":
		crv = elliptic.P384()
	case "P-521":
		crv = elliptic.P521()
	default:
		return nil, 0, fmt.Errorf("Unsupported ECC curve '%s'", ec.Curve)
	}
	return crv, crv.Params().BitSize / 8, nil
}

func (ec *jwkEC) PublicKey() (*ecdsa.PublicKey, error) {
	crv, byteLen, err := ec.params()
	if err != nil {
		return nil, err
	}

	if len(ec.X.Bytes()) != byteLen {
		return nil, fmt.Errorf("X coordinate must be %d byte length for curve '%s'. Got '%d'", byteLen, ec.Curve, len(ec.X.Bytes()))
	}
	if len(ec.Y.Bytes()) != byteLen {
		return nil, fmt.Errorf("Y coordinate must be %d byte length for curve '%s'. Got '%d'", byteLen, ec.Curve, len(ec.Y.Bytes()))
	}

	return &ecdsa.PublicKey{
		Curve: crv,
		X:     ec.X.Int,
		Y:     ec.Y.Int,
	}, nil
}

func (ec *jwkEC) PrivateKey() (*ecdsa.PrivateKey, error) {
	pubkey, err := ec.PublicKey()
	if err != nil {
		return nil, err
	}
	_, byteLen, err := ec.params()
	if err != nil {
		return nil, err
	}

	if len(ec.D.Bytes()) != byteLen {
		return nil, fmt.Errorf("D coordinate must be %d byte length for curve '%s'. Got '%d'", byteLen, ec.Curve, len(ec.D.Bytes()))
	}

	return &ecdsa.PrivateKey{
		PublicKey: *pubkey,
		D:         ec.D.Int,
	}, nil
}

type jwkSymmetric struct {
	jwk
	K octet `json:"k" ` // Symmetric key
}

func (js *jwkSymmetric) Key() []byte {
	return js.K.Bytes()
}

func (jwk JWK) MarshalJSON() ([]byte, error) {
	return jwk.raw, nil
}
