package keyutil

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestParseJWK(t *testing.T) {
	tests := []struct {
		Name                string
		InputFile           string // one of InputFile or Input is used
		Input               string
		Expected            JWK
		ExpectedErrContains string
	}{
		{
			Name:      "Valid EC JWK",
			InputFile: "testdata/test-jwk-ec.json",
			Expected: JWK{

				KeyType: "EC",
				KeyID:   "test-key-ecc-p256",
			},
		},
		{

			Name:      "Valid symmetric JWK",
			InputFile: "testdata/test-jwk-symmetric.json",
			Expected: JWK{

				KeyType: "oct",
				KeyID:   "test-symmetric-key",
			},
		},
		{
			Name:                "Invalid JSON",
			Input:               `{"kty": malformed`,
			ExpectedErrContains: "parse",
		},
		{
			Name:                "Empty input",
			Input:               "",
			ExpectedErrContains: "parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			var actual JWK
			var actualErr error
			if tc.InputFile != "" {
				actual, actualErr = ReadJWKFile(tc.InputFile)
			} else {
				actual, actualErr = ReadJWK([]byte(tc.Input))
			}

			if actualErr != nil {
				if !strings.Contains(actualErr.Error(), tc.ExpectedErrContains) {
					Diff(t, tc.ExpectedErrContains, actualErr.Error(), "Wrong error")
				}
				return
			}

			Diff(t, tc.Expected, actual, "Wrong JWK", cmpopts.IgnoreUnexported(JWK{}))
		})
	}
}

// Avoid an import cycle
func TestJWKMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name                string
		inputFile           string
		expectedErrContains string
	}{
		{
			name:      "EC Key Round Trip",
			inputFile: "testdata/test-jwk-ec.json",
		},
		{
			name:      "Symmetric Key Round Trip",
			inputFile: "testdata/test-jwk-symmetric.json",
		},
	}

	// Test cases will be implemented in next step
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Implementation will be added in next step
		})
	}
}

func Diff(t *testing.T, expected, actual interface{}, msg string, opts ...cmp.Option) bool {
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("%s (-want +got):\n%s", msg, diff)
		return true
	}
	return false
}
