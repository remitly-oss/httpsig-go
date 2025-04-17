package keyutil_test

import (
	"strings"
	"testing"

	"github.com/remitly-oss/httpsig-go/keyutil"
	"github.com/remitly-oss/httpsig-go/sigtest"
)

func TestParseJWK(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    keyutil.JWK
		wantErr string
	}{
		{
			name:  "Valid EC JWK",
			input: sigtest.MustReadFile("../testdata/test-jwk-ec.json"),
			want: keyutil.JWK{
				KeyType: "EC",
				KeyID:   "test-key-ecc-p256",
			},
		},
		{
			name:  "Valid symmetric JWK",
			input: sigtest.MustReadFile("../testdata/test-jwk-symmetric.json"),
			want: keyutil.JWK{
				KeyType: "oct",
				KeyID:   "test-symmetric-key",
			},
		},
		{
			name:    "Invalid JSON",
			input:   []byte(`{"kty": malformed`),
			wantErr: "Failed to json parse JWK public key",
		},
		{
			name:    "Empty input",
			input:   []byte{},
			wantErr: "Failed to json parse JWK public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyutil.ParseJWK(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("ParseJWK() error = nil, want error containing %q", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseJWK() error = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseJWK() unexpected error = %v", err)
				return
			}

			if got.KeyType != tt.want.KeyType {
				t.Errorf("ParseJWK() KeyType = %v, want %v", got.KeyType, tt.want.KeyType)
			}
			if got.Algorithm != tt.want.Algorithm {
				t.Errorf("ParseJWK() Algorithm = %v, want %v", got.Algorithm, tt.want.Algorithm)
			}
			if got.KeyID != tt.want.KeyID {
				t.Errorf("ParseJWK() KeyID = %v, want %v", got.KeyID, tt.want.KeyID)
			}
		})
	}
}
