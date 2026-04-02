// Package types defines shared types used across the httpsig module.
package types

// Algorithm identifies the cryptographic signing algorithm.
type Algorithm string

const (
	Algo_RSA_PSS_SHA512    Algorithm = "rsa-pss-sha512"
	Algo_RSA_v1_5_sha256   Algorithm = "rsa-v1_5-sha256"
	Algo_HMAC_SHA256       Algorithm = "hmac-sha256"
	Algo_ECDSA_P256_SHA256 Algorithm = "ecdsa-p256-sha256"
	Algo_ECDSA_P384_SHA384 Algorithm = "ecdsa-p384-sha384"
	Algo_ED25519           Algorithm = "ed25519"
)

// Symmetric reports whether the algorithm uses a shared secret rather than
// an asymmetric key pair.
func (a Algorithm) Symmetric() bool {
	return a == Algo_HMAC_SHA256
}

// MetadataProvider gives read access to the signature metadata parameters on
// an individual signature.
type MetadataProvider interface {
	Created() (int, error)
	Expires() (int, error)
	Nonce() (string, error)
	Alg() (string, error)
	KeyID() (string, error)
	Tag() (string, error)
}
