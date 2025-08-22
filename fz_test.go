package httpsig

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/remitly-oss/httpsig-go/sigtest"
)

// FuzzSigningOptions fuzzes the basic user input to SigningOptions
func FuzzSigningOptions1(f *testing.F) {
	testcases := [][]string{
		{"", "", "", ""},
		{"", "0", "0", "\xde"},
		{"", "\n", "0", "0"},
		{"", "", "0", "@"},
		{"", "@query-param", "0", "0"},
		{string(Algo_ECDSA_P256_SHA256), "@query", "0", "0"},
		{"any", "@query", "0", "0"},
		{string(Algo_ED25519), "@query", "0", "0"},
	}

	for _, tc := range testcases {
		f.Add(tc[0], tc[1], tc[2], tc[3])
	}

	reqtxt, err := os.ReadFile("testdata/rfc-test-request.txt")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, algo, label, keyID, tag string) {
		t.Logf("Label: %s\n", label)
		t.Logf("keyid: %s\n", keyID)
		t.Logf("tag: %s\n", tag)

		fields := Fields(label, keyID, tag)
		fields = append(fields, SignedField{
			Name: label,
			Parameters: map[string]any{
				keyID: tag,
			},
		})
		privKey := sigtest.ReadTestPrivateKey(t, "test-key-ed25519.key")
		so := SigningProfile{
			Algorithm: Algo_ED25519,
			Fields:    Fields(label, keyID, tag),
			Metadata:  []Metadata{MetaKeyID, MetaTag},
			Label:     label,
		}
		sk := SigningKey{
			Key:       privKey,
			MetaKeyID: keyID,
			MetaTag:   tag,
		}
		if so.validate(sk) != nil {
			// Catching invalidate signing options is good.
			return
		}

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(reqtxt)))
		if err != nil {
			t.Fatal(err)
		}

		err = Sign(req, so, sk)
		if err != nil {
			if _, ok := err.(*SignatureError); ok {
				// Handled error
				return
			}
			// Unhandled error
			t.Error(err)
		}
	})
}

func FuzzSigningOptionsFields(f *testing.F) {
	testcases := [][]string{
		{"", "", ""},
		{"0", "0", "\xde"},
		{"\n", "0", "0"},
		{"", "0", "@"},
		{"@query-param", "name", "0"},
		{"@query", "0", "0"},
		{"@method", "", ""},
		{"@status", "", ""},
	}

	for _, tc := range testcases {
		f.Add(tc[0], tc[1], tc[2])
	}

	reqtxt, err := os.ReadFile("testdata/rfc-test-request.txt")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, field, tagName, tagValue string) {
		t.Logf("field: %s\n", field)
		t.Logf("tag: %s:%s\n", tagName, tagValue)
		fields := []SignedField{}
		if tagName == "" {
			fields = append(fields, SignedField{
				Name: field,
			})
		} else {
			fields = append(fields, SignedField{
				Name: field,
				Parameters: map[string]any{
					tagName: tagValue,
				},
			})
		}

		so := SigningProfile{
			Algorithm: Algo_ED25519,
			Fields:    fields,
		}
		sk := SigningKey{
			Key: sigtest.ReadTestPrivateKey(t, "test-key-ed25519.key"),
		}
		if so.validate(sk) != nil {
			// Catching invalidate signing options is good.
			return
		}

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(reqtxt)))
		if err != nil {
			t.Fatal(err)
		}

		err = Sign(req, so, sk)
		if err != nil {
			if _, ok := err.(*SignatureError); ok {
				// Handled error
				return
			}
			// Unhandled error
			t.Error(err)
		}
	})
}

func FuzzExtractSignatures(f *testing.F) {
	testcases := []struct {
		SignatureHeader      string
		SignatureInputHeader string
	}{
		{
			SignatureHeader:      "",
			SignatureInputHeader: "",
		},
		{
			SignatureHeader:      "sig-b24=(\"@status\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"",
			SignatureInputHeader: "sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:",
		},
		{"sig1=:dGVzdA==:", "sig1=(\"@method\",   \"@target-uri\");created=1618884473"},
		{"sig1=:invalid-base64:", "sig1=(\"@method\");created=1618884473"},
		{"sig1", "sig1=()"},
		{"sig1=:dGVzdA==:, sig2=:dGVzdA==:", "sig1=(\"@method\"), sig2=(\"@path\")"},
		{"sig1=invalid", "sig1=(\"@method\")"},
		{"sig1=:dGVzdA==:", "sig1=invalid"},
		{"=:dGVzdA==:", "=(\"@method\")"},
		{"sig1=:dGVzdA==:", "sig1=("},
		{
			SignatureInputHeader: `tst-ecdsa-0=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-1=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-2=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-3=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-4=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-5=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-6=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa", tst-ecdsa-7=("content-digest" "@method" "@target-uri");created=1755899955;keyid="test-key-ecdsa"`,
			SignatureHeader:      `tst-ecdsa-0=:ktNUTq0MYt1iIDU8AxBi39Nrw6vVLAD7BL1EMuHxtmpDatYx7CFxxFee1cPqE3hkOKknGnQgS6Umrv0ct3wq3A==:, tst-ecdsa-1=:XFoz0EbrdxZFhsvVi0xhRBI2F5NNaQ5SsdRUjmyBiaTqZvC7Ud15gD+AmTipZxyjx5iX9YNKDNAnILv0fViWHA==:, tst-ecdsa-2=:EmUtrfTosRFr1uIKCu89ggqpfUClw4La3C3esWuXYdcg7xntY5dpqoqFCwyrlwxHveLcBxoHcVp1trSGsUJGAA==:, tst-ecdsa-3=:jJw65CIeODTbYxTAqBPof9U70FU1+uL/k8GLLJR3YMOHbk5enJqi9GCI6Gpn7SUamw1d3u6YqUb9BYo2C1WdTA==:, tst-ecdsa-4=:yhFGqoxuKpzApUccnjspLYhneYXf9Y/CTNbrCrQuzRUf6OzDGJFxJB1deDwdLJzIGB2DnICNVtHc3Zp/MI5+jQ==:, tst-ecdsa-5=:jxZ+G1ZFY9yc0GyhTXG5vSKtHTEQ2Slacb6AJzV8lHuuoTJpn08eZeJijLXhiRzBNzHEoFc9PwcsKehIp5dGjA==:, tst-ecdsa-6=:HLFRyXXkrIZbRYEoVQl3aL1EpFtg52JkAK8wad+wHnehVFYzO3M7tyEpdGBcr/6ZpUr1rkc1J1Ru9wRa3WkqRQ==:, tst-ecdsa-7=:b7+mkQt02cvV/cucQcSn9J+lJ9/cRkWcVX8mAdNh+p3avD1ULj/hg0z7ZkgEnlfDuWaTskdu+CLncxseLsEIWQ==:`,
		},
	}

	for _, tc := range testcases {
		f.Add(tc.SignatureHeader, tc.SignatureInputHeader)
	}

	reqtxt, err := os.ReadFile("testdata/rfc-test-request.txt")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, sigHeader, sigInputHeader string) {
		t.Logf("signature header: %s\n", sigHeader)
		t.Logf("signature input header: %s\n", sigInputHeader)

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(reqtxt)))
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("signature", sigHeader)
		req.Header.Set("signature-input", sigInputHeader)

		sigSFV, err := parseSignaturesFromRequest(req.Header, false)
		if err != nil {
			return
		}
		for _, label := range sigSFV.Sigs.Names() {
			_, err = unmarshalSignature(sigSFV, label)
			if err != nil {
				if _, ok := err.(*SignatureError); ok {
					// Handled error
					return
				}
				// Unhandled error
				t.Error(err)
			}
		}
	})
}

// FuzzComponentIDParsing tests component identifier parsing edge cases
func FuzzComponentIDParsing(f *testing.F) {
	testcases := []struct {
		name       string
		parameters map[string]string
	}{
		{"@method", nil},
		{"@target-uri", nil},
		{"@query-param", map[string]string{"name": "test"}},
		{"content-digest", nil},
		{"", nil},
		{"@invalid-component", nil},
		{"header-with-unicode-😀", nil},
		{"@query-param", map[string]string{"name": ""}},
		{"@query-param", map[string]string{"": "value"}},
	}

	for _, tc := range testcases {
		params := ""
		for k, v := range tc.parameters {
			params += fmt.Sprintf(";%s=%s", k, v)
		}
		f.Add(tc.name, params)
	}

	f.Fuzz(func(t *testing.T, name, paramStr string) {
		// Create a SignedField with fuzzed input
		field := SignedField{Name: name}

		// Parse parameters string into map
		if paramStr != "" {
			field.Parameters = make(map[string]any)
			pairs := strings.Split(paramStr, ";")
			for _, pair := range pairs {
				if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
					field.Parameters[kv[0]] = kv[1]
				}
			}
		}

		// Convert to componentID - should not panic
		cID := field.componentID()

		// Try to get signature name and value
		_, err := cID.signatureName()
		if err != nil {
			var sigErr *SignatureError
			if !errors.As(err, &sigErr) {
				t.Errorf("Expected SignatureError, got: %T", err)
			}
		}

		req := httptest.NewRequest("GET",
			"http://example.com/test?param=value", nil)
		req.Header.Set("Content-Digest",
			"sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
		msg := httpMessage{Req: req}

		_, err = cID.signatureValue(msg)
		if err != nil {
			var sigErr *SignatureError
			if !errors.As(err, &sigErr) {
				t.Errorf("Expected SignatureError, got: %T", err)
			}
		}
	})
}
