package sigkeydraft_test

import (
	"net/http"
	"testing"

	sigkey "github.com/remitly-oss/httpsig-go/sigkeydraft"
)

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		wantErr     bool
		wantLabels  []string
		wantSchemes map[string]sigkey.Scheme
	}{
		{
			name:        "single jwt entry",
			header:      `sig1=jwt;jwt="eyJ.payload.sig"`,
			wantLabels:  []string{"sig1"},
			wantSchemes: map[string]sigkey.Scheme{"sig1": sigkey.SchemeJWT},
		},
		{
			name:        "multiple entries",
			header:      `sig1=jwt;jwt="tok1", sig2=jwt;jwt="tok2"`,
			wantLabels:  []string{"sig1", "sig2"},
			wantSchemes: map[string]sigkey.Scheme{"sig1": sigkey.SchemeJWT, "sig2": sigkey.SchemeJWT},
		},
		{
			name:        "jwks_uri entry",
			header:      `sig1=jwks_uri;id="https://client.example";dwk="example-configuration";kid="key-1"`,
			wantLabels:  []string{"sig1"},
			wantSchemes: map[string]sigkey.Scheme{"sig1": sigkey.SchemeJWKSURI},
		},
		{
			name:        "mixed jwt and jwks_uri",
			header:      `sig1=jwt;jwt="eyJ.payload.sig", sig2=jwks_uri;id="https://client.example";dwk="example-configuration";kid="key-1"`,
			wantLabels:  []string{"sig1", "sig2"},
			wantSchemes: map[string]sigkey.Scheme{"sig1": sigkey.SchemeJWT, "sig2": sigkey.SchemeJWKSURI},
		},
		{
			name:    "empty header",
			header:  "",
			wantErr: true,
		},
		{
			name:    "invalid sfv",
			header:  "!!!",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := sigkey.ParseHeader(tc.header)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, label := range tc.wantLabels {
				e, ok := entries[label]
				if !ok {
					t.Errorf("missing entry for label %q", label)
					continue
				}
				if wantScheme, ok := tc.wantSchemes[label]; ok {
					if e.Scheme != wantScheme {
						t.Errorf("entry %q scheme: got %q, want %q", label, e.Scheme, wantScheme)
					}
				}
			}
		})
	}
}

func TestSigKeyJWT(t *testing.T) {
	header := `sig1=jwt;jwt="eyJ.payload.sig"`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	e := entries["sig1"]
	got, err := e.JWT()
	if err != nil {
		t.Fatalf("JWT(): %v", err)
	}
	if got != "eyJ.payload.sig" {
		t.Errorf("JWT() = %q, want %q", got, "eyJ.payload.sig")
	}
}

func TestSigKeyJWT_Missing(t *testing.T) {
	// A valid entry with no jwt param
	header := `sig1=jwt`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	_, err = entries["sig1"].JWT()
	if err == nil {
		t.Fatal("expected error for missing jwt param, got nil")
	}
}

func TestSigKeyJWKSURI(t *testing.T) {
	const wantID = "https://client.example"
	const wantDWK = "example-configuration"
	const wantKID = "key-1"
	header := `sig1=jwks_uri;id="` + wantID + `";dwk="` + wantDWK + `";kid="` + wantKID + `"`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	gotID, err := entries["sig1"].ID()
	if err != nil {
		t.Fatalf("ID(): %v", err)
	}
	if gotID != wantID {
		t.Errorf("ID() = %q, want %q", gotID, wantID)
	}
	gotDWK, err := entries["sig1"].DWK()
	if err != nil {
		t.Fatalf("DWK(): %v", err)
	}
	if gotDWK != wantDWK {
		t.Errorf("DWK() = %q, want %q", gotDWK, wantDWK)
	}
	gotKID, err := entries["sig1"].KID()
	if err != nil {
		t.Fatalf("KID(): %v", err)
	}
	if gotKID != wantKID {
		t.Errorf("KID() = %q, want %q", gotKID, wantKID)
	}
}

func TestSigKeyJWKSURI_Missing(t *testing.T) {
	header := `sig1=jwks_uri`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	_, err = entries["sig1"].ID()
	if err == nil {
		t.Fatal("expected error for missing id param, got nil")
	}
}

func TestSigKeyStringParam(t *testing.T) {
	header := `sig1=jwt;jwt="mytoken"`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	got, err := entries["sig1"].StringParam("jwt")
	if err != nil {
		t.Fatalf("StringParam: %v", err)
	}
	if got != "mytoken" {
		t.Errorf("StringParam() = %q, want %q", got, "mytoken")
	}
}

func TestDeriveHeader_JWT(t *testing.T) {
	sk, err := sigkey.NewSigKey("sig1", sigkey.SchemeJWT, sigkey.ParametersJWT{JWT: "eyJ.payload.sig"})
	if err != nil {
		t.Fatalf("NewSigKey: %v", err)
	}
	value, err := sk.DeriveHeader("")
	if err != nil {
		t.Fatalf("DeriveHeader: %v", err)
	}
	entries, err := sigkey.ParseHeader(value)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	e, ok := entries["sig1"]
	if !ok {
		t.Fatal("missing entry for sig1")
	}
	if e.Scheme != sigkey.SchemeJWT {
		t.Errorf("scheme: got %q, want %q", e.Scheme, sigkey.SchemeJWT)
	}
	got, err := e.JWT()
	if err != nil {
		t.Fatalf("JWT(): %v", err)
	}
	if got != "eyJ.payload.sig" {
		t.Errorf("JWT() = %q, want %q", got, "eyJ.payload.sig")
	}
}

func TestDeriveHeader_AppendToExisting(t *testing.T) {
	sk1, err := sigkey.NewSigKey("sig1", sigkey.SchemeJWT, sigkey.ParametersJWT{JWT: "token1"})
	if err != nil {
		t.Fatalf("NewSigKey sig1: %v", err)
	}
	value, err := sk1.DeriveHeader("")
	if err != nil {
		t.Fatalf("DeriveHeader sig1: %v", err)
	}

	const wantID = "https://example.com"
	const wantDWK = "example-configuration"
	const wantKID = "key-1"
	sk2, err := sigkey.NewSigKey("sig2", sigkey.SchemeJWKSURI, sigkey.ParametersJWKSURI{ID: wantID, DWK: wantDWK, KID: wantKID})
	if err != nil {
		t.Fatalf("NewSigKey sig2: %v", err)
	}
	value, err = sk2.DeriveHeader(value)
	if err != nil {
		t.Fatalf("DeriveHeader sig2: %v", err)
	}

	entries, err := sigkey.ParseHeader(value)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if tok, _ := entries["sig1"].JWT(); tok != "token1" {
		t.Errorf("sig1 jwt = %q, want %q", tok, "token1")
	}
	if id, _ := entries["sig2"].ID(); id != wantID {
		t.Errorf("sig2 id = %q, want %q", id, wantID)
	}
}

func TestDeriveHeader_HWK_OmitsEmptyFields(t *testing.T) {
	sk, err := sigkey.NewSigKey("sig1", sigkey.SchemeHWK, sigkey.ParametersHWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "someXvalue",
		Y:   "someYvalue",
	})
	if err != nil {
		t.Fatalf("NewSigKey: %v", err)
	}
	value, err := sk.DeriveHeader("")
	if err != nil {
		t.Fatalf("DeriveHeader: %v", err)
	}
	entries, err := sigkey.ParseHeader(value)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	e := entries["sig1"]
	for _, name := range []string{"kty", "crv", "x", "y"} {
		if _, ok := e.Param(name); !ok {
			t.Errorf("missing param %q", name)
		}
	}
	// RSA fields should be absent
	for _, name := range []string{"n", "e"} {
		if _, ok := e.Param(name); ok {
			t.Errorf("param %q should be absent (omitempty)", name)
		}
	}
}

func TestNewSigKey_NonStructError(t *testing.T) {
	if _, err := sigkey.NewSigKey("sig1", sigkey.SchemeJWT, "not-a-struct"); err == nil {
		t.Fatal("expected error for non-struct params")
	}
}

func TestParseHeader_JKTJWTScheme(t *testing.T) {
	header := `sig1=jkt-jwt;jwt="eyJ.payload.sig"`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	e, ok := entries["sig1"]
	if !ok {
		t.Fatal("missing entry for sig1")
	}
	if e.Scheme != sigkey.SchemeJKTJWT {
		t.Errorf("scheme: got %q, want %q", e.Scheme, sigkey.SchemeJKTJWT)
	}
	got, err := e.JWT()
	if err != nil {
		t.Fatalf("JWT(): %v", err)
	}
	if got != "eyJ.payload.sig" {
		t.Errorf("JWT() = %q, want %q", got, "eyJ.payload.sig")
	}
}

func TestDeriveHeader_JKTJWTScheme(t *testing.T) {
	sk, err := sigkey.NewSigKey("sig1", sigkey.SchemeJKTJWT, sigkey.ParametersJKTJWT{JWT: "eyJ.payload.sig"})
	if err != nil {
		t.Fatalf("NewSigKey: %v", err)
	}
	value, err := sk.DeriveHeader("")
	if err != nil {
		t.Fatalf("DeriveHeader: %v", err)
	}
	entries, err := sigkey.ParseHeader(value)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	e, ok := entries["sig1"]
	if !ok {
		t.Fatal("missing entry for sig1")
	}
	if e.Scheme != sigkey.SchemeJKTJWT {
		t.Errorf("scheme: got %q, want %q", e.Scheme, sigkey.SchemeJKTJWT)
	}
	got, err := e.JWT()
	if err != nil {
		t.Fatalf("JWT(): %v", err)
	}
	if got != "eyJ.payload.sig" {
		t.Errorf("JWT() = %q, want %q", got, "eyJ.payload.sig")
	}
}

func TestParseSignatureError_Basic(t *testing.T) {
	header := `error=invalid_signature`
	se, err := sigkey.ParseSignatureError(header)
	if err != nil {
		t.Fatalf("ParseSignatureError: %v", err)
	}
	if se.Code != sigkey.ErrCodeInvalidSignature {
		t.Errorf("Code: got %q, want %q", se.Code, sigkey.ErrCodeInvalidSignature)
	}
	if len(se.SupportedAlgorithms) != 0 {
		t.Errorf("SupportedAlgorithms: got %v, want empty", se.SupportedAlgorithms)
	}
}

func TestParseSignatureError_UnsupportedAlgorithm(t *testing.T) {
	header := `error=unsupported_algorithm, supported_algorithms=("ed25519" "ecdsa-p256-sha256")`
	se, err := sigkey.ParseSignatureError(header)
	if err != nil {
		t.Fatalf("ParseSignatureError: %v", err)
	}
	if se.Code != sigkey.ErrCodeUnsupportedAlgorithm {
		t.Errorf("Code: got %q, want %q", se.Code, sigkey.ErrCodeUnsupportedAlgorithm)
	}
	want := []string{"ed25519", "ecdsa-p256-sha256"}
	if len(se.SupportedAlgorithms) != len(want) {
		t.Fatalf("SupportedAlgorithms: got %v, want %v", se.SupportedAlgorithms, want)
	}
	for i, alg := range want {
		if se.SupportedAlgorithms[i] != alg {
			t.Errorf("SupportedAlgorithms[%d]: got %q, want %q", i, se.SupportedAlgorithms[i], alg)
		}
	}
}

func TestParseSignatureError_InvalidInput(t *testing.T) {
	header := `error=invalid_input, required_input=("@method" "@path")`
	se, err := sigkey.ParseSignatureError(header)
	if err != nil {
		t.Fatalf("ParseSignatureError: %v", err)
	}
	if se.Code != sigkey.ErrCodeInvalidInput {
		t.Errorf("Code: got %q, want %q", se.Code, sigkey.ErrCodeInvalidInput)
	}
	want := []string{"@method", "@path"}
	if len(se.RequiredInput) != len(want) {
		t.Fatalf("RequiredInput: got %v, want %v", se.RequiredInput, want)
	}
	for i, inp := range want {
		if se.RequiredInput[i] != inp {
			t.Errorf("RequiredInput[%d]: got %q, want %q", i, se.RequiredInput[i], inp)
		}
	}
}

func TestSetSignatureError_RoundTrip(t *testing.T) {
	h := make(http.Header)
	se := sigkey.SignatureError{
		Code:                sigkey.ErrCodeUnsupportedAlgorithm,
		SupportedAlgorithms: []string{"ed25519", "ecdsa-p256-sha256"},
	}
	if err := sigkey.SetSignatureError(h, se); err != nil {
		t.Fatalf("SetSignatureError: %v", err)
	}
	value := h.Get(sigkey.SignatureErrorHeader)
	if value == "" {
		t.Fatal("Signature-Error header not set")
	}
	got, err := sigkey.ParseSignatureError(value)
	if err != nil {
		t.Fatalf("ParseSignatureError: %v", err)
	}
	if got.Code != se.Code {
		t.Errorf("Code: got %q, want %q", got.Code, se.Code)
	}
	if len(got.SupportedAlgorithms) != len(se.SupportedAlgorithms) {
		t.Fatalf("SupportedAlgorithms len: got %d, want %d", len(got.SupportedAlgorithms), len(se.SupportedAlgorithms))
	}
	for i := range se.SupportedAlgorithms {
		if got.SupportedAlgorithms[i] != se.SupportedAlgorithms[i] {
			t.Errorf("SupportedAlgorithms[%d]: got %q, want %q", i, got.SupportedAlgorithms[i], se.SupportedAlgorithms[i])
		}
	}
}

func TestParseSignatureError_MissingErrorMember(t *testing.T) {
	_, err := sigkey.ParseSignatureError(`foo=bar`)
	if err == nil {
		t.Fatal("expected error for missing 'error' member")
	}
}

func TestParseSignatureError_Invalid(t *testing.T) {
	_, err := sigkey.ParseSignatureError("!!!")
	if err == nil {
		t.Fatal("expected error for invalid SFV")
	}
}
