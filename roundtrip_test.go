package httpsig_test

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyutil"
)

func TestRoundTrip(t *testing.T) {

	testcases := []struct {
		Name        string
		Params      httpsig.SigningOptions
		RequestFile string
		Keys        httpsig.KeyFetcher
		Profile     httpsig.VerifyProfile
	}{
		{
			Name: "RSA-PSS",
			Params: httpsig.SigningOptions{
				PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-rsa-pss.key", keyutil.PKCS8_RSAPSS),
				Algorithm:  httpsig.Algo_RSA_PSS_SHA512,
				Fields:     httpsig.DefaultRequiredFields,
				Metadata:   []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:      "tst-rsa-pss",
				MetaKeyID:  "test-key-rsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa": {
					KeyID:  "test-key-rsa",
					Algo:   httpsig.Algo_RSA_PSS_SHA512,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-rsa-pss.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name: "RSA-v15",
			Params: httpsig.SigningOptions{
				PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/key-rsa-v15.key"),
				Algorithm:  httpsig.Algo_RSA_v1_5_sha256,
				Fields:     httpsig.DefaultRequiredFields,
				Metadata:   []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:      "tst-rsa-pss",
				MetaKeyID:  "test-key-rsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa": {
					KeyID:  "test-key-rsa",
					Algo:   httpsig.Algo_RSA_v1_5_sha256,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/key-rsa-v15.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name: "HMAC_SHA256",
			Params: httpsig.SigningOptions{
				Secret:    mustReadFile("testdata/test-shared-secret"),
				Algorithm: httpsig.Algo_HMAC_SHA256,
				Fields:    httpsig.DefaultRequiredFields,
				Metadata:  []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				MetaKeyID: "test-key-shared",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-shared": {
					KeyID:  "test-key-shared",
					Algo:   httpsig.Algo_HMAC_SHA256,
					Secret: mustReadFile("testdata/test-shared-secret"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name: "ECDSA-p265",
			Params: httpsig.SigningOptions{
				PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ecc-p256.key", keyutil.ECC),
				Algorithm:  httpsig.Algo_ECDSA_P256_SHA256,
				Fields:     httpsig.DefaultRequiredFields,
				Metadata:   []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:      "tst-ecdsa",
				MetaKeyID:  "test-key-ecdsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ecdsa": {
					KeyID:  "test-key-ecds",
					Algo:   httpsig.Algo_ECDSA_P256_SHA256,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ecc-p256.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name: "ECDSA-p384",
			Params: httpsig.SigningOptions{
				PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ecc-p384.key", keyutil.ECC),
				Algorithm:  httpsig.Algo_ECDSA_P384_SHA384,
				Fields:     httpsig.DefaultRequiredFields,
				Metadata:   []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:      "tst-ecdsa",
				MetaKeyID:  "test-key-ecdsa",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ecdsa": {
					KeyID:  "test-key-ecdsa",
					Algo:   httpsig.Algo_ECDSA_P384_SHA384,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ecc-p384.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
		{
			Name: "ED25519",
			Params: httpsig.SigningOptions{
				PrivateKey: keyutil.MustReadPrivateKeyFile("testdata/test-key-ed25519.key"),
				Algorithm:  httpsig.Algo_ED25519,
				Fields:     httpsig.DefaultRequiredFields,
				Metadata:   []httpsig.Metadata{httpsig.MetaCreated, httpsig.MetaKeyID},
				Label:      "tst-ed",
				MetaKeyID:  "test-key-ed",
			},
			RequestFile: "rfc-test-request.txt",
			Keys: keyutil.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-ed": {
					KeyID:  "test-key-ed",
					Algo:   httpsig.Algo_ED25519,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-ed25519.pub"),
				},
			}),
			Profile: httpsig.DefaultVerifyProfile,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			signer, err := httpsig.NewSigner(tc.Params)
			if err != nil {
				t.Fatal(err)
			}

			req := readRequest(t, tc.RequestFile)
			err = signer.Sign(req)
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
				t.Fatalf("%#v", err)
			}
			t.Logf("%+v\n", vf)
		})

	}
}

func readRequest(t testing.TB, reqFile string) *http.Request {
	reqtxt, err := os.Open(fmt.Sprintf("testdata/%s", reqFile))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.ReadRequest(bufio.NewReader(reqtxt))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mustReadFile(file string) []byte {
	data, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return data
}
