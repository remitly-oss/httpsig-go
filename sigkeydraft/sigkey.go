// Package sigkey parses the Signature-Key HTTP header defined in
// draft-hardt-httpbis-signature-key. It has no dependency on the parent
// httpsig package and can be used standalone.
//
// This package does not perform any validation of keys or certificates and is only responsible for parsing the Signature-Key header.
package sigkeydraft

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	sfv "github.com/dunglas/httpsfv"
)

type Scheme string

const (
	// Header is the canonical name of the Signature-Key HTTP header.
	Header = "Signature-Key"

	SchemeHWK     Scheme = "hwk"
	SchemeJWKSURI Scheme = "jwks_uri"
	SchemeX509    Scheme = "x509"
	SchemeJWT     Scheme = "jwt"
	SchemeJKTJWT  Scheme = "jkt-jwt"
)

type ParametersHWK struct {
	Kty string `sfv:"kty,omitempty"`
	Crv string `sfv:"crv,omitempty"`
	X   string `sfv:"x,omitempty"`
	Y   string `sfv:"y,omitempty"`
	// RSA
	N string `sfv:"n,omitempty"`
	E string `sfv:"e,omitempty"`
}

type ParametersJWT struct {
	JWT string `sfv:"jwt"`
}

// ParametersJKTJWT are the parameters for the jkt-jwt scheme. The JWT must
// have its signing key in the jwk header parameter and its typ must be
// "jkt-s256+jwt" or "jkt-s512+jwt".
type ParametersJKTJWT struct {
	JWT string `sfv:"jwt"`
}

// ParametersJWKSURI are the parameters for the jwks_uri scheme.
// The verifier fetches {ID}/.well-known/{DWK} to obtain the JWKS URI,
// then retrieves the key matching KID.
type ParametersJWKSURI struct {
	// ID is the signer identifier (HTTPS URL).
	ID string `sfv:"id"`
	// DWK is the dot well-known metadata document name under /.well-known/.
	DWK string `sfv:"dwk"`
	// KID is the key identifier within the JWKS.
	KID string `sfv:"kid"`
}

type ParametersX509 struct {
	X5U string `sfv:"x5u"`
	// X5T is the base64url-encoded SHA-256 hash of the DER-encoded
	// end-entity certificate. Required per draft-04.
	X5T string `sfv:"x5t"`
}

// SigKeyHeader is one parsed entry from the Signature-Key header dictionary.
// Each entry corresponds to a single signature label.
type SigKeyHeader struct {
	// Label is the signature label (dictionary key), e.g. "sig1".
	Label string
	// Scheme is the key-transport scheme token, e.g. "jwt".
	Scheme Scheme
	// params holds the raw SFV parameters for scheme-specific values.
	params *sfv.Params
}

// NewSigKey constructs a SigKeyHeader from a label, scheme, and one of the
// Parameters structs. The resulting value can be serialized into a
// Signature-Key header value via DeriveHeader.
func NewSigKey(label string, scheme Scheme, params any) (SigKeyHeader, error) {
	item := sfv.NewItem(sfv.Token(scheme))
	if err := structToSFVParams(params, item.Params); err != nil {
		return SigKeyHeader{}, fmt.Errorf("sigkey: %w", err)
	}
	return SigKeyHeader{
		Label:  label,
		Scheme: scheme,
		params: item.Params,
	}, nil
}

// ParseHeader parses a Signature-Key header value as an SFV Dictionary and
// returns a map from signature label to SigKey. Returns an error if the value
// is empty, not a valid SFV dictionary, or any entry has a malformed scheme.
func ParseHeader(headerValue string) (map[string]SigKeyHeader, error) {
	dict, err := sfv.UnmarshalDictionary([]string{headerValue})
	if err != nil {
		return nil, fmt.Errorf("sigkey: failed to parse Signature-Key header as SFV dictionary: %w", err)
	}

	names := dict.Names()
	if len(names) == 0 {
		return nil, fmt.Errorf("sigkey: Signature-Key header is empty")
	}

	entries := make(map[string]SigKeyHeader, len(names))
	for _, label := range names {
		member, _ := dict.Get(label)
		item, ok := member.(sfv.Item)
		if !ok {
			return nil, fmt.Errorf("sigkey: entry %q must be an SFV Item, got %T", label, member)
		}

		var scheme Scheme
		switch v := item.Value.(type) {
		case sfv.Token:
			scheme = Scheme(v)
		case string:
			scheme = Scheme(v)
		default:
			return nil, fmt.Errorf("sigkey: scheme for entry %q must be a token or string, got %T", label, item.Value)
		}

		entries[label] = SigKeyHeader{
			Label:  label,
			Scheme: scheme,
			params: item.Params,
		}
	}
	return entries, nil
}

// Param returns the raw SFV parameter value for the given name, along with
// whether it was present. This provides access to scheme-specific parameters
// (e.g. "jwt") without the caller needing to know the SFV types.
func (e SigKeyHeader) Param(name string) (any, bool) {
	return e.params.Get(name)
}

// StringParam returns the named parameter as a string. Returns an error if
// the parameter is absent or is not a string value.
func (e SigKeyHeader) StringParam(name string) (string, error) {
	v, ok := e.params.Get(name)
	if !ok {
		return "", fmt.Errorf("sigkey: entry %q has no parameter %q", e.Label, name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("sigkey: entry %q parameter %q has unexpected type %T", e.Label, name, v)
	}
	return s, nil
}

// JWT returns the unvalidated JWT string from the entry's parameters.
// Used for both the jwt and jkt-jwt schemes, both of which carry the JWT in
// the "jwt" parameter.
func (e SigKeyHeader) JWT() (string, error) {
	s, err := e.StringParam("jwt")
	if err != nil {
		return "", fmt.Errorf("sigkey: entry %q is missing required 'jwt' parameter: %w", e.Label, err)
	}
	return s, nil
}

// ID returns the signer identifier (HTTPS URL) from a jwks_uri entry.
func (e SigKeyHeader) ID() (string, error) {
	s, err := e.StringParam("id")
	if err != nil {
		return "", fmt.Errorf("sigkey: entry %q is missing required 'id' parameter: %w", e.Label, err)
	}
	return s, nil
}

// DWK returns the dot well-known metadata document name from a jwks_uri entry.
func (e SigKeyHeader) DWK() (string, error) {
	s, err := e.StringParam("dwk")
	if err != nil {
		return "", fmt.Errorf("sigkey: entry %q is missing required 'dwk' parameter: %w", e.Label, err)
	}
	return s, nil
}

// KID returns the key identifier from a jwks_uri entry.
func (e SigKeyHeader) KID() (string, error) {
	s, err := e.StringParam("kid")
	if err != nil {
		return "", fmt.Errorf("sigkey: entry %q is missing required 'kid' parameter: %w", e.Label, err)
	}
	return s, nil
}

func (skh SigKeyHeader) SetHeader(h http.Header) error {
	//		h.Set(Header, 	skh.DeriveHeader(h.Get(Header))
	updated, err := skh.DeriveHeader(h.Get(Header))
	if err != nil {
		return err
	}
	h.Set(Header, updated)
	return nil
}

// DeriveHeader returns the value to set for a Signature-Key header, adding or
// replacing the entry for label. existing is the current header value (empty
// string if the header is not yet set). scheme is the key-transport token
// (e.g. SchemeJWT). params must be a pointer to or value of one of the
// Parameters structs (ParametersJWT, ParametersHWK, ParametersJWKSURI,
// ParametersX509). Fields are mapped to SFV parameters using the "sfv" struct
// tag; fields tagged with "omitempty" are skipped when zero.
func (skh SigKeyHeader) DeriveHeader(existingHeader string) (string, error) {
	var dict *sfv.Dictionary
	if existingHeader != "" {
		var err error
		dict, err = sfv.UnmarshalDictionary([]string{existingHeader})
		if err != nil {
			return "", fmt.Errorf("sigkey: failed to parse existing Signature-Key header: %w", err)
		}
	} else {
		dict = sfv.NewDictionary()
	}

	item := sfv.NewItem(sfv.Token(skh.Scheme))
	for _, name := range skh.params.Names() {
		v, _ := skh.params.Get(name)
		item.Params.Add(name, v)
	}
	dict.Add(skh.Label, item)

	value, err := sfv.Marshal(dict)
	if err != nil {
		return "", fmt.Errorf("sigkey: failed to marshal Signature-Key header: %w", err)
	}
	return value, nil
}

// structToSFVParams populates p from the exported fields of v using "sfv"
// struct tags. The tag format is `sfv:"name"` or `sfv:"name,omitempty"`.
// Only string fields are supported; other types return an error.
func structToSFVParams(v any, p *sfv.Params) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("params must be a struct, got %T", v)
	}
	rt := rv.Type()
	for i := range rt.NumField() {
		field := rt.Field(i)
		tag := field.Tag.Get("sfv")
		if tag == "" || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		omitempty := opts == "omitempty"

		fv := rv.Field(i)
		if omitempty && fv.IsZero() {
			continue
		}

		switch fv.Kind() {
		case reflect.String:
			p.Add(name, fv.String())
		default:
			return fmt.Errorf("unsupported field type %s for param %q", fv.Type(), name)
		}
	}
	return nil
}
