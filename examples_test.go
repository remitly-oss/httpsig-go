package httpsig_test

import (
	"net/http/httptest"

	"github.com/remitly-oss/httpsig"
	"github.com/remitly-oss/httpsig/keyutil"
)

func ExampleSign() {
	pkeyEncoded := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNTK6255ubaaj1i/c
ppuLouTgjAVyHGSxI0pYX8z1e2GhRANCAASkbVuWv1KXXs2H8b0ruFLyv2lKJWtT
BznPJ5sSI1Jn+srosJB/GbEZ3Kg6PcEi+jODF9fdpNEaHGbbGdaVhJi1
-----END PRIVATE KEY-----`

	pkey, _ := keyutil.ReadPrivateKey([]byte(pkeyEncoded))
	req := httptest.NewRequest("GET", "https://example.com/data", nil)

	params := httpsig.SigningOptions{
		PrivateKey: pkey,
		Algorithm:  httpsig.Algo_ECDSA_P256_SHA256,
		Fields:     httpsig.DefaultRequiredFields,
		Metadata:   []httpsig.Metadata{httpsig.MetaKeyID},
		MetaKeyID:  "key123",
	}

	signer, _ := httpsig.NewSigner(params)
	signer.Sign(req)
}

func ExampleVerify() {
	pubkeyEncoded := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIUctKvU5L/eEYxua5Zlz0HIQJRQq
MTQ7eYQXwqpTvTJkuTffGXKLilT75wY2YZWfybv9flu5d6bCfw+4UB9+cg==
-----END PUBLIC KEY-----`

	pubkey, _ := keyutil.ReadPublicKey([]byte(pubkeyEncoded))
	req := httptest.NewRequest("GET", "https://example.com/data", nil)

	kf := keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
		"key123": {
			KeyID:  "key123",
			Algo:   httpsig.Algo_ECDSA_P256_SHA256,
			PubKey: pubkey,
		},
	})

	httpsig.Verify(req, kf, httpsig.DefaultVerifyProfile)
}
