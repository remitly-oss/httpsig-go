package httpsig

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/remitly-oss/httpsig-go/sigtest"
)

func TestValidateProfile(t *testing.T) {
	testcases := []struct {
		Name        string
		Sig         extractedSignature
		Profile     VerifyProfile
		KeySpecAlgo Algorithm
		Expected    ErrCode // Expected ErrCode if an error. Empty string if expecting no error
		ExpectedMsg string
	}{
		// Signature Label Validation Tests
		{
			Name: "ValidSignatureLabel",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{{Name: "content-digest"}, {Name: "@method"}, {Name: "@target-uri"}},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(1755206251),
						},
					},
				},
			},
			Profile: VerifyProfile{
				SignatureLabel:    "sig1",
				AllowedAlgorithms: []Algorithm{Algo_ECDSA_P256_SHA256},
				RequiredFields:    Fields("content-digest", "@method", "@target-uri"),
				RequiredMetadata:  []Metadata{MetaCreated, MetaKeyID},
				nowTime: func() time.Time {
					return time.Unix(int64(1755206251), 0)
				},
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},
		{
			Name: "InvalidSignatureLabel",
			Sig: extractedSignature{
				Label:     "sig2",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				SignatureLabel: "sig1",
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature label 'sig2' does not match required label 'sig1'",
		},
		{
			Name: "EmptySignatureLabelInProfile",
			Sig: extractedSignature{
				Label:     "sig2",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				SignatureLabel: "", // Empty means any label is acceptable
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},

		// Algorithm Validation Tests
		{
			Name: "ValidAlgorithm",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				AllowedAlgorithms: []Algorithm{Algo_ECDSA_P256_SHA256, Algo_ED25519},
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},
		{
			Name: "InvalidAlgorithm",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				AllowedAlgorithms: []Algorithm{Algo_ECDSA_P256_SHA256, Algo_ED25519},
			},
			KeySpecAlgo: Algo_RSA_PSS_SHA512,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Algorithm 'rsa-pss-sha512' is not in allowed algorithms list",
		},
		{
			Name: "NoAllowedAlgorithmsRestriction",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				AllowedAlgorithms: []Algorithm{}, // Empty means any algorithm is acceptable
			},
			KeySpecAlgo: Algo_RSA_PSS_SHA512,
			Expected:    ErrCode(""),
		},

		// Required Fields Validation Tests
		{
			Name: "ValidRequiredFields",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						{Name: "@method"},
						{Name: "@target-uri"},
						{Name: "authorization"}, // Extra field is OK
					},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredFields: Fields("content-digest", "@method", "@target-uri"),
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},
		{
			Name: "MissingRequiredField",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						{Name: "@method"},
						// Missing @target-uri
					},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredFields: Fields("content-digest", "@method", "@target-uri"),
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature missing required field '@target-uri'",
		},
		{
			Name: "CaseInsensitiveFieldMatching",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"}, // lowercase in signature
						{Name: "authorization"},  // lowercase in signature
					},
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredFields: Fields("Content-Digest", "Authorization"), // Mixed case in profile
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},
		{
			Name: "NoRequiredFields",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{}, // Empty components is OK when no fields required
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredFields: []SignedField{}, // No fields required
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},

		// Required Metadata Validation Tests
		{
			Name: "ValidRequiredMetadata",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID, MetaNonce}, // Extra metadata is OK
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(1755206251),
						},
					},
				},
			},
			Profile: VerifyProfile{
				RequiredMetadata: []Metadata{MetaCreated, MetaKeyID},
				nowTime: func() time.Time {
					return time.Unix(int64(1755206251), 0)
				},
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},
		{
			Name: "MissingRequiredMetadata",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated}, // Missing MetaKeyID
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredMetadata: []Metadata{MetaCreated, MetaKeyID},
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature missing required meta parameter 'keyid'",
		},

		// Disallowed Metadata Validation Tests
		{
			Name: "DisallowedMetaAlgorithm",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{{Name: "content-digest"}, {Name: "@method"}, {Name: "@target-uri"}},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID, MetaAlgorithm}, // This should be disallowed
					MetadataValues: nil,
				},
			},
			Profile:     DefaultVerifyProfile,
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature contains disallowed meta parameter 'alg'",
		},
		{
			Name: "NoDisallowedMetadata",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID}, // Only allowed metadata
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(1755206251),
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisallowedMetadata: []Metadata{MetaAlgorithm},
				nowTime: func() time.Time {
					return time.Unix(int64(1755206251), 0)
				},
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},

		// Complex Validation Tests (Multiple Rules)
		{
			Name: "ComplexValidSignature",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						{Name: "@method"},
						{Name: "@target-uri"},
					},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(1755206251),
						},
					},
				},
			},
			Profile: VerifyProfile{
				SignatureLabel:     "sig1",
				AllowedAlgorithms:  []Algorithm{Algo_ECDSA_P256_SHA256, Algo_ED25519},
				RequiredFields:     Fields("content-digest", "@method", "@target-uri"),
				RequiredMetadata:   []Metadata{MetaCreated, MetaKeyID},
				DisallowedMetadata: []Metadata{MetaAlgorithm},
				nowTime: func() time.Time {
					return time.Unix(int64(1755206251), 0)
				},
			},
			KeySpecAlgo: Algo_ED25519,
			Expected:    ErrCode(""),
		},
		{
			Name: "ComplexInvalidSignature_MultipleFailures",
			Sig: extractedSignature{
				Label:     "sig2", // Wrong label
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						// Missing @method and @target-uri
					},
					MetadataParams: []Metadata{MetaAlgorithm}, // Disallowed metadata, missing required
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				SignatureLabel:     "sig1",
				AllowedAlgorithms:  []Algorithm{Algo_ECDSA_P256_SHA256},
				RequiredFields:     Fields("content-digest", "@method", "@target-uri"),
				RequiredMetadata:   []Metadata{MetaCreated, MetaKeyID},
				DisallowedMetadata: []Metadata{MetaAlgorithm},
			},
			KeySpecAlgo: Algo_RSA_PSS_SHA512, // Not allowed algorithm
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature label 'sig2' does not match required label 'sig1'", // First error encountered
		},

		// DefaultVerifyProfile Tests
		{
			Name: "DefaultVerifyProfile_Valid",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						{Name: "@method"},
						{Name: "@target-uri"},
					},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: time.Now().Unix(),
						},
					},
				},
			},
			Profile:     DefaultVerifyProfile,
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrCode(""),
		},
		{
			Name: "DefaultVerifyProfile_InvalidAlgorithm",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						{Name: "@method"},
						{Name: "@target-uri"},
					},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID},
					MetadataValues: nil,
				},
			},
			Profile:     DefaultVerifyProfile,
			KeySpecAlgo: Algo_RSA_v1_5_sha256, // Not in DefaultVerifyProfile allowed algorithms
			Expected:    ErrSigProfile,
			ExpectedMsg: "Algorithm 'rsa-v1_5-sha256' is not in allowed algorithms list",
		},
		{
			Name: "DefaultVerifyProfile_MissingRequiredFields",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components: []componentID{
						{Name: "content-digest"},
						// Missing @method and @target-uri required by DefaultVerifyProfile
					},
					MetadataParams: []Metadata{MetaCreated, MetaKeyID},
					MetadataValues: nil,
				},
			},
			Profile:     DefaultVerifyProfile,
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature missing required field '@method'",
		},

		// Edge Cases
		{
			Name: "EmptySignatureComponents",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{}, // No components
					MetadataParams: []Metadata{},
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredFields: Fields("content-digest"), // But we require some fields
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature missing required field 'content-digest'",
		},
		{
			Name: "EmptyMetadata",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{}, // No metadata
					MetadataValues: nil,
				},
			},
			Profile: VerifyProfile{
				RequiredMetadata: []Metadata{MetaCreated}, // But we require some metadata
			},
			KeySpecAlgo: Algo_ECDSA_P256_SHA256,
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature missing required meta parameter 'created'",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Profile.validate(tc.Sig, tc.KeySpecAlgo)
			if tc.Expected == ErrCode("") {
				sigtest.Diff(t, nil, err, "Diff")
				return
			}
			var sigErr *SignatureError
			if errors.As(err, &sigErr) {
				sigtest.Diff(t, tc.Expected, sigErr.Code, "Unexpected error code")
				if tc.ExpectedMsg != "" && err != nil {
					if !strings.Contains(sigErr.Message, tc.ExpectedMsg) {
						t.Errorf("Expected error message to contain '%s', got: %s", tc.ExpectedMsg, err.Error())
					}
				}
			} else {
				t.Fatal("Error was not type *SignatureError")
			}

		})
	}
}

func TestValidateTiming(t *testing.T) {
	now := time.Now()

	testcases := []struct {
		Name        string
		Sig         extractedSignature
		Profile     VerifyProfile
		Expected    ErrCode // Expected ErrCode if an error. Empty string if expecting no error
		ExpectedMsg string
	}{
		// DisableTimeEnforcement Tests
		{
			Name: "TimeEnforcementDisabled_ExpiredSignature",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-2 * time.Hour).Unix()), // Very old
							MetaExpires: int64(now.Add(-1 * time.Hour).Unix()), // Expired
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableTimeEnforcement: true, // Should ignore all timing issues
			},
			Expected: ErrCode(""),
		},
		{
			Name: "TimeEnforcementEnabled_SameSignature",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-2 * time.Hour).Unix()),
							MetaExpires: int64(now.Add(-1 * time.Hour).Unix()),
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableTimeEnforcement: false,
				CreatedValidDuration:   time.Minute * 5, // Only 5 minutes allowed
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "is older than allowed duration",
		},

		// Created Time Validation Tests
		{
			Name: "ValidCreatedTime",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-2 * time.Minute).Unix()), // 2 minutes ago
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration: time.Minute * 5, // Allow 5 minutes
			},
			Expected: ErrCode(""),
		},
		{
			Name: "CreatedTimeTooOld",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-10 * time.Minute).Unix()), // 10 minutes ago
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration: time.Minute * 5, // Only allow 5 minutes
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "is older than allowed duration",
		},
		{
			Name: "CreatedTimeInFuture",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(5 * time.Minute).Unix()), // 5 minutes in future
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration: time.Minute * 10,
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "is too far in the future",
		},
		{
			Name: "CreatedTimeSlightlyInFuture_Allowed",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(30 * time.Second).Unix()), // 30 seconds in future (clock skew)
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration: time.Minute * 10,
			},
			Expected: ErrCode(""), // Should be allowed due to clock skew tolerance
		},
		// Expires Time Validation Tests
		{
			Name: "ValidExpiresTime",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaExpires: int64(now.Add(5 * time.Minute).Unix()), // Expires in 5 minutes
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableExpirationEnforcement: false,
			},
			Expected: ErrCode(""),
		},
		{
			Name: "ExpiredSignature",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaExpires: int64(now.Add(-5 * time.Minute).Unix()), // Expired 5 minutes ago
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableExpirationEnforcement: false,
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature expired at",
		},
		{
			Name: "ExpiredSignature_WithinSkewTolerance",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaExpires: int64(now.Add(-30 * time.Second).Unix()), // Expired 30 seconds ago
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableExpirationEnforcement: false,
				ExpiredSkew:                  time.Minute, // Allow 1 minute skew
			},
			Expected: ErrCode(""), // Should be allowed within skew tolerance
		},
		{
			Name: "ExpirationEnforcementDisabled",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaExpires: int64(now.Add(-1 * time.Hour).Unix()), // Very expired
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableExpirationEnforcement: true, // Should ignore expiration
			},
			Expected: ErrCode(""),
		},

		// Complex Timing Tests
		{
			Name: "BothCreatedAndExpires_Valid",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-2 * time.Minute).Unix()), // 2 minutes ago
							MetaExpires: int64(now.Add(3 * time.Minute).Unix()),  // 3 minutes from now
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration:         time.Minute * 5,
				DisableExpirationEnforcement: false,
			},
			Expected: ErrCode(""),
		},
		{
			Name: "BothCreatedAndExpires_CreatedTooOld",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-10 * time.Minute).Unix()), // 10 minutes ago
							MetaExpires: int64(now.Add(3 * time.Minute).Unix()),   // 3 minutes from now
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration:         time.Minute * 5, // Only allow 5 minutes
				DisableExpirationEnforcement: false,
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "is older than allowed duration", // Created validation fails first
		},
		{
			Name: "BothCreatedAndExpires_Expired",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated, MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							MetaCreated: int64(now.Add(-2 * time.Minute).Unix()), // 2 minutes ago (valid)
							MetaExpires: int64(now.Add(-3 * time.Minute).Unix()), // Expired 3 minutes ago
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration:         time.Minute * 5,
				DisableExpirationEnforcement: false,
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "Signature expired at",
		},

		// Error Handling Tests
		{
			Name: "InvalidCreatedMetadata",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaCreated},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							// Missing MetaCreated value
						},
					},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration: time.Minute * 5,
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "Failed to get created timestamp",
		},
		{
			Name: "InvalidExpiresMetadata",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{MetaExpires},
					MetadataValues: fixedMetadataProvider{
						values: map[Metadata]any{
							// Missing MetaExpires value
						},
					},
				},
			},
			Profile: VerifyProfile{
				DisableExpirationEnforcement: false,
			},
			Expected:    ErrSigProfile,
			ExpectedMsg: "Failed to get expires timestamp",
		},

		// No Metadata Present Tests
		{
			Name: "NoCreatedMetadata_NoValidation",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{}, // No created metadata
					MetadataValues: fixedMetadataProvider{values: map[Metadata]any{}},
				},
			},
			Profile: VerifyProfile{
				CreatedValidDuration: time.Minute * 5,
			},
			Expected: ErrCode(""), // Should pass since no created time to validate
		},
		{
			Name: "NoExpiresMetadata_NoValidation",
			Sig: extractedSignature{
				Label:     "sig1",
				Signature: []byte{},
				Input: sigBaseInput{
					Components:     []componentID{},
					MetadataParams: []Metadata{}, // No expires metadata
					MetadataValues: fixedMetadataProvider{values: map[Metadata]any{}},
				},
			},
			Profile: VerifyProfile{
				DisableExpirationEnforcement: false,
			},
			Expected: ErrCode(""), // Should pass since no expires time to validate
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Profile.validateTiming(tc.Sig, now)
			if tc.Expected == ErrCode("") {
				sigtest.Diff(t, nil, err, "Diff")
				return
			}
			var sigErr *SignatureError
			if errors.As(err, &sigErr) {
				sigtest.Diff(t, tc.Expected, sigErr.Code, "Unexpected error code")
				if tc.ExpectedMsg != "" && err != nil {
					if !strings.Contains(sigErr.Message, tc.ExpectedMsg) {
						t.Errorf("Expected error message to contain '%s', got: %s", tc.ExpectedMsg, err.Error())
					}
				}
			} else {
				t.Fatal("Error was not type *SignatureError")
			}
		})
	}
}
