package httpsig_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
	"github.com/remitly-oss/httpsig-go/keyutil"
	"github.com/remitly-oss/httpsig-go/sigtest"
)

func TestVerify(t *testing.T) {
	testcases := []struct {
		Name        string
		RequestFile string
		Keys        httpsig.KeyFetcher
		Expected    httpsig.VerifyResult
	}{
		{
			Name:        "OneValid",
			RequestFile: "verify_request1.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa-pss": {
					KeyID:  "test-key-rsa-pss",
					Algo:   httpsig.Algo_RSA_PSS_SHA512,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-rsa-pss.pub"),
				},
			}),
			Expected: httpsig.VerifyResult{
				Signatures: map[string]httpsig.VerifiedSignature{
					"sig-b21": {
						Label: "sig-b21",
						MetadataProvider: &fixedMetadataProvider{map[httpsig.Metadata]any{
							httpsig.MetaKeyID:   "test-key-rsa-pss",
							httpsig.MetaCreated: int64(1618884473),
							httpsig.MetaNonce:   "b3k2pp5k7z-50gnwp.yemd",
						}},
					},
				},
				InvalidSignatures: map[string]httpsig.InvalidSignature{},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			actual, err := httpsig.Verify(sigtest.ReadRequest(t, tc.RequestFile), tc.Keys, httpsig.DefaultVerifyProfile)
			if err != nil {
				t.Fatal(err)
			}
			// VerifyResult is returned even when error is also returned.
			sigtest.Diff(t, tc.Expected, actual, "Did not match", getCmdOpts()...)
		})
	}
}

func TestVerifyInvalid(t *testing.T) {
	testcases := []struct {
		Name        string
		RequestFile string
		Keys        httpsig.KeyFetcher
		Expected    httpsig.VerifyResult
	}{
		{
			Name:        "ExtractFailure",
			RequestFile: "verify_request2.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa-pss": {
					KeyID:  "test-key-rsa-pss",
					Algo:   httpsig.Algo_RSA_PSS_SHA512,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-rsa-pss.pub"),
				},
			}),
			Expected: httpsig.VerifyResult{
				Signatures: map[string]httpsig.VerifiedSignature{
					"sig-b21": {
						Label: "sig-b21",
						MetadataProvider: &fixedMetadataProvider{map[httpsig.Metadata]any{
							httpsig.MetaKeyID:   "test-key-rsa-pss",
							httpsig.MetaCreated: int64(1618884473),
							httpsig.MetaNonce:   "b3k2pp5k7z-50gnwp.yemd",
						}},
					},
				},
				InvalidSignatures: map[string]httpsig.InvalidSignature{
					"bad-sig": createInvalidSignature(httpsig.InvalidSignature{
						Label:       "bad-sig",
						HasMetadata: true,
					}, &fixedMetadataProvider{map[httpsig.Metadata]any{
						httpsig.MetaKeyID:   "test-key-rsa-pss",
						httpsig.MetaCreated: int64(1618884473),
					}}),
				},
			},
		},
		{
			Name:        "OneValid-OneInvalid",
			RequestFile: "verify_request2.txt",
			Keys: keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
				"test-key-rsa-pss": {
					KeyID:  "test-key-rsa-pss",
					Algo:   httpsig.Algo_RSA_PSS_SHA512,
					PubKey: keyutil.MustReadPublicKeyFile("testdata/test-key-rsa-pss.pub"),
				},
			}),
			Expected: httpsig.VerifyResult{
				Signatures: map[string]httpsig.VerifiedSignature{
					"sig-b21": {
						Label: "sig-b21",
						MetadataProvider: &fixedMetadataProvider{map[httpsig.Metadata]any{
							httpsig.MetaKeyID:   "test-key-rsa-pss",
							httpsig.MetaCreated: int64(1618884473),
							httpsig.MetaNonce:   "b3k2pp5k7z-50gnwp.yemd",
						}},
					},
				},
				InvalidSignatures: map[string]httpsig.InvalidSignature{
					"bad-sig": createInvalidSignature(httpsig.InvalidSignature{
						Label:       "bad-sig",
						HasMetadata: true,
					}, &fixedMetadataProvider{map[httpsig.Metadata]any{
						httpsig.MetaKeyID:   "test-key-rsa-pss",
						httpsig.MetaCreated: int64(1618884473),
					}}),
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			actual, err := httpsig.Verify(sigtest.ReadRequest(t, tc.RequestFile), tc.Keys, httpsig.DefaultVerifyProfile)
			if err == nil {
				t.Fatal("Expected verify error and invalid sigature responsse")
			}
			// VerifyResult is returned even when error is also returned.
			sigtest.Diff(t, tc.Expected, actual, "Did not match", getCmdOpts()...)
		})
	}
}

type fixedMetadataProvider struct {
	values map[httpsig.Metadata]any
}

func (fmp fixedMetadataProvider) Created() (int, error) {
	if val, ok := fmp.values[httpsig.MetaCreated]; ok {
		return int(val.(int64)), nil
	}
	return 0, fmt.Errorf("No created value")
}

func (fmp fixedMetadataProvider) Expires() (int, error) {
	if val, ok := fmp.values[httpsig.MetaExpires]; ok {
		return int(val.(int64)), nil
	}
	return 0, fmt.Errorf("No expires value")
}

func (fmp fixedMetadataProvider) Nonce() (string, error) {
	if val, ok := fmp.values[httpsig.MetaNonce]; ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No nonce value")
}

func (fmp fixedMetadataProvider) Alg() (string, error) {
	if val, ok := fmp.values[httpsig.MetaAlgorithm]; ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No alg value")
}

func (fmp fixedMetadataProvider) KeyID() (string, error) {
	if val, ok := fmp.values[httpsig.MetaKeyID]; ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No keyid value")
}

func (fmp fixedMetadataProvider) Tag() (string, error) {
	if val, ok := fmp.values[httpsig.MetaTag]; ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No tag value")
}

func metaVal[E comparable](f1 func() (E, error)) any {
	val, err := f1()
	if err != nil {
		return err.Error()
	}
	return val
}

func getCmdOpts() []cmp.Option {
	return []cmp.Option{
		cmp.Transformer("Metadata", TransformMeta),
	}

}
func TransformMeta(md httpsig.MetadataProvider) map[string]any {
	out := map[string]any{}

	out[string(httpsig.MetaCreated)] = metaVal(md.Created)
	out[string(httpsig.MetaExpires)] = metaVal(md.Expires)
	out[string(httpsig.MetaNonce)] = metaVal(md.Nonce)
	out[string(httpsig.MetaAlgorithm)] = metaVal(md.Alg)
	out[string(httpsig.MetaKeyID)] = metaVal(md.KeyID)
	out[string(httpsig.MetaTag)] = metaVal(md.Tag)
	return out
}

func createInvalidSignature(input httpsig.InvalidSignature, md httpsig.MetadataProvider) httpsig.InvalidSignature {
	is := httpsig.InvalidSignature{
		MetadataProvider: md,
	}
	is.Error = input.Error
	is.HasMetadata = input.HasMetadata
	is.Label = input.Label
	is.Raw = input.Raw
	return is
}
