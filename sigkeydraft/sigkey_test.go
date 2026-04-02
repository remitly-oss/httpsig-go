package sigkeydraft_test

import (
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
			header:      `sig1=jwks_uri;jwks_uri="https://device.example.com/.well-known/jwks.json"`,
			wantLabels:  []string{"sig1"},
			wantSchemes: map[string]sigkey.Scheme{"sig1": sigkey.SchemeJWKSURI},
		},
		{
			name:        "mixed jwt and jwks_uri",
			header:      `sig1=jwt;jwt="eyJ.payload.sig", sig2=jwks_uri;jwks_uri="https://device.example.com/.well-known/jwks.json"`,
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
	const wantURI = "https://device.example.com/.well-known/jwks.json"
	header := `sig1=jwks_uri;jwks_uri="` + wantURI + `"`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	got, err := entries["sig1"].JWKSURI()
	if err != nil {
		t.Fatalf("JWKSURI(): %v", err)
	}
	if got != wantURI {
		t.Errorf("JWKSURI() = %q, want %q", got, wantURI)
	}
}

func TestSigKeyJWKSURI_Missing(t *testing.T) {
	header := `sig1=jwks_uri`
	entries, err := sigkey.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	_, err = entries["sig1"].JWKSURI()
	if err == nil {
		t.Fatal("expected error for missing jwks_uri param, got nil")
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

	const wantURI = "https://example.com/.well-known/jwks.json"
	sk2, err := sigkey.NewSigKey("sig2", sigkey.SchemeJWKSURI, sigkey.ParametersJWKSURI{JWKSURI: wantURI})
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
	if uri, _ := entries["sig2"].JWKSURI(); uri != wantURI {
		t.Errorf("sig2 jwks_uri = %q, want %q", uri, wantURI)
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
