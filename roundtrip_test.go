package httpsig_test

import (
	"crypto"
	"testing"

	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
	"github.com/remitly-oss/httpsig-go/keyutil"
	"github.com/remitly-oss/httpsig-go/sigtest"
)

// TestRoundTrip tests that the signing code can be verified by the verify code.
func TestRoundTrip(t *testing.T) {

	testcases := []struct {
		Name                  string
		PrivateKey            crypto.PrivateKey
		Secret                []byte
		Params                httpsig.SigningProfile
		RequestFile           string
		Keys                  httpsig.KeyFetcher
		Profile               httpsig.VerifyProfile
		ExpectedErrCodeVerify httpsig.ErrCode
	}{
		{
			Name:       "RSA-PSS",
			PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-rsa-pss.key"),
			Params: httpsig.SigningProfile{
				Algorithm: httpsig.Algo_RSA_PSS_SHA512,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:     "tst-rsa-pss",
				MetaKeyID: "test-key-rsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa": {
					KeyID:  "test-key-rsa",
					Algo:   httpsig.Algo_RSA_PSS_SHA512,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-rsa-pss.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name:       "RSA-v15",
			PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/key-rsa-v15.key"),
			Params: httpsig.SigningProfile{
				Algorithm: httpsig.Algo_RSA_v1_5_sha256,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:     "tst-rsa-pss",
				MetaKeyID: "test-key-rsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa": {
					KeyID:  "test-key-rsa",
					Algo:   httpsig.Algo_RSA_v1_5_sha256,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/key-rsa-v15.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name:   "HMAC_SHA256",
			Secret: sigtest.MustReadFile("testdata/test-shared-secret"),
			Params: httpsig.SigningProfile{
				Algorithm: httpsig.Algo_HMAC_SHA256,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				MetaKeyID: "test-key-shared",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-shared": {
					KeyID:  "test-key-shared",
					Algo:   httpsig.Algo_HMAC_SHA256,
					Secret: sigtest.MustReadFile("testdata/test-shared-secret"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name:       "ECDSA-p265",
			PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ecc-p256.key"),
			Params: httpsig.SigningProfile{
				Algorithm: httpsig.Algo_ECDSA_P256_SHA256,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:     "tst-ecdsa",
				MetaKeyID: "test-key-ecdsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ecdsa": {
					KeyID:  "test-key-ecds",
					Algo:   httpsig.Algo_ECDSA_P256_SHA256,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ecc-p256.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name:       "ECDSA-p384",
			PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ecc-p384.key"),
			Params: httpsig.SigningProfile{
				Algorithm: httpsig.Algo_ECDSA_P384_SHA384,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:     "tst-ecdsa",
				MetaKeyID: "test-key-ecdsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ecdsa": {
					KeyID:  "test-key-ecdsa",
					Algo:   httpsig.Algo_ECDSA_P384_SHA384,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ecc-p384.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name:       "ED25519",
			PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ed25519.key"),
			Params: httpsig.SigningProfile{
				Algorithm: httpsig.Algo_ED25519,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:     "tst-ed",
				MetaKeyID: "test-key-ed",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ed": {
					KeyID:  "test-key-ed",
					Algo:   httpsig.Algo_ED25519,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ed25519.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name:       "BadDigest",
			PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ed25519.key"),
			Params: httpsig.SigningProfile{

				Algorithm: httpsig.Algo_ED25519,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:     "tst-content-digest",
				MetaKeyID: "test-key-ed",
			},
			RequestFile: "request_bad_digest.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ed": {
					KeyID:  "test-key-ed",
					Algo:   httpsig.Algo_ED25519,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ed25519.pub"),
				},
			}),
			Profile:               httpsig.DefaultVerifyProfile,
			ExpectedErrCodeVerify: httpsig.ErrNoSigWrongDigest,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			var signer *httpsig.Signer
			if isSymmetric(tc.Params.Algorithm) {
				var err error
				signer, err = httpsig.NewSignerWithSecret(tc.Params, tc.Secret)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				signer, err = httpsig.NewSigner(tc.Params, tc.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
			}

			req := sigtest.ReadRequest(t, tc.RequestFile)
			err := signer.Sign(req)
			if err != nil {
				t.Fatalf("%#v", err)
			}
			t.Log(req.Header.Get("Signature-Input"))
			t.Log(req.Header.Get("Signature"))
			ver, err := httpsig.NewVerifier(tc.Keys, tc.Profile)
			if err != nil {
				t.Fatal(err)
			}
			vf, err := ver.Verify(req)
			if err != nil {
				if tc.ExpectedErrCodeVerify != "" {
					if sigerr, ok := err.(*httpsig.SignatureError); ok {
						sigtest.Diff(t, tc.ExpectedErrCodeVerify, sigerr.Code, "Wrong err code")
					}
				} else {
					t.Fatalf("%#v", err)
				}
			} else if tc.ExpectedErrCodeVerify != "" {
				t.Fatal("Expected error")
			}
			t.Logf("%+v\n", vf)
		})

	}
}

func isSymmetric(a httpsig.Algorithm) bool {
	switch a {
	case httpsig.Algo_HMAC_SHA256:
		return true
	}
	return false
}
