package httpsig

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	sfv "github.com/dunglas/httpsfv"
)

type Algorithm string
type Digest string

// Metadata are the named signature metadata parameters
type Metadata string

type CreatedScheme int
type ExpiresScheme int
type NonceScheme int

const (
	// Supported signing algorithms
	Algo_RSA_PSS_SHA512    Algorithm = "rsa-pss-sha512"
	Algo_RSA_v1_5_sha256   Algorithm = "rsa-v1_5-sha256"
	Algo_HMAC_SHA256       Algorithm = "hmac-sha256"
	Algo_ECDSA_P256_SHA256 Algorithm = "ecdsa-p256-sha256"
	Algo_ECDSA_P384_SHA384 Algorithm = "ecdsa-p384-sha384"
	Algo_ED25519           Algorithm = "ed25519"

	DigestSHA256 Digest = "sha-256"
	DigestSHA512 Digest = "sha-512"

	// Signature metadata parameters
	MetaCreated   Metadata = "created"
	MetaExpires   Metadata = "expires"
	MetaNonce     Metadata = "nonce"
	MetaAlgorithm Metadata = "alg"
	MetaKeyID     Metadata = "keyid"
	MetaTag       Metadata = "tag"

	// DefaultSignatureLabel is the label that will be used for a signature if not label is provided in the parameters.
	// A request can contain multiple signatures therefore each signature is labeled.
	DefaultSignatureLabel = "sig1"

	// Nonce schemes
	NonceRandom32 = iota // 32 bit random nonce. Base64 encoded
)

type SigningOptions struct {
	PrivateKey crypto.PrivateKey // Required for asymetric algorithms
	Secret     []byte            // Required for HMAC signing
	Algorithm  Algorithm
	Digest     Digest        // The http digest algorithm to apply. Defaults to sha-256.
	Fields     []SignedField // Fields and Derived components to sign
	Metadata   []Metadata    // Metadata parameters to add to the signature
	Label      string        // The signature label. Defaults to DefaultSignatureLabel

	// Signature metadata settings.
	// These are only added to the signature if the parameter is listed in the Metadata list.
	MetaKeyID           string        // 'keyid' - No default. A value must be provided if the parameter is in Metadata.
	MetaTag             string        // 'tag' - No default. A value must be provided if the parameter is in Metadata.
	MetaExpiresDuration time.Duration // 'expires' - Current time plus this duration. Default duration 5 minutes.
	MetaNonce           NonceScheme   // 'nonce' - Defaults to NonceRandom32
	// Algorithm is the metdata value if 'alg' is included in the Metadata list.
}

// MetadataProvider allows customized functions for metadata parameter values. Not needed for default usage.
type MetadataProvider interface {
	Created() (int, error)
	Expires() (int, error)
	Nonce() (string, error)
	Alg() (string, error)
	KeyID() (string, error)
	Tag() (string, error)
}

func (so SigningOptions) Created() (int, error) {
	return int(time.Now().Unix()), nil
}

func (so SigningOptions) Expires() (int, error) {
	return int(time.Now().Add(so.MetaExpiresDuration).Unix()), nil
}

func (so SigningOptions) Nonce() (string, error) {
	switch so.MetaNonce {
	case NonceRandom32:
		return genNonce(), nil
	}
	return "", fmt.Errorf("Invalid nonce scheme '%d'", so.MetaNonce)
}

func (so SigningOptions) Alg() (string, error) {
	return string(so.Algorithm), nil
}

func (so SigningOptions) KeyID() (string, error) {
	return so.MetaKeyID, nil
}
func (so SigningOptions) Tag() (string, error) {
	return so.MetaTag, nil
}

// SignedField indicates which part of the request or response to use for signing.
// This is the 'message component' in the specification.
type SignedField struct {
	Name       string
	Parameters map[string]any // Parameters are modifiers applied to the field that changes the way the signature is calculated.
}

type signedFields []SignedField

func (sf signedFields) includes(field string) bool {
	target := strings.ToLower(field)
	for _, fld := range sf {
		if fld.Name == target {
			return true
		}
	}
	return false
}

// Fields turns a list of fields into the full specification. Used when the signed fields/components do not need to specify any parameters
func Fields(fields ...string) []SignedField {
	all := []SignedField{}
	for _, field := range fields {
		all = append(all, SignedField{
			Name:       strings.ToLower(field),
			Parameters: map[string]any{},
		})
	}
	return all
}

func Sign(req *http.Request, params SigningOptions, mdp ...MetadataProvider) error {
	s, err := NewSigner(params, mdp...)
	if err != nil {
		return err
	}
	return s.Sign(req)
}

type Signer struct {
	options SigningOptions
	mdp     MetadataProvider
}

func NewSigner(params SigningOptions, mdp ...MetadataProvider) (*Signer, error) {
	err := params.validate()
	if err != nil {
		return nil, err
	}
	opts := params.withDefaults()
	s := &Signer{
		options: opts,
		mdp:     opts,
	}
	if len(mdp) > 0 {
		s.mdp = mdp[0]
	}
	return s, nil
}

// Sign signs the request and adds the signature headers to the request.
// If the signature fields includes Content-Digest and Content-Digest is not already included in the request then Sign will read the request body to calculate the digest and set the header.  The request body will be replaced with a new io.ReaderCloser.
func (s *Signer) Sign(req *http.Request) error {
	// Add the content-digest if covered by the signature and not already present
	if signedFields(s.options.Fields).includes("content-digest") && req.Header.Get("Content-Digest") == "" {
		di, err := digestBody(s.options.Digest, req.Body)
		if err != nil {
			return err
		}
		req.Body = di.NewBody
		digestValue, err := createDigestHeader(s.options.Digest, di.Digest)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Digest", digestValue)
	}

	baseParams, err := s.options.baseParameters(s.mdp)
	if err != nil {
		return err
	}

	return sign(
		httpMessage{
			Req: req,
		}, sigParameters{
			Base:       baseParams,
			Algo:       s.options.Algorithm,
			PrivateKey: s.options.PrivateKey,
			Secret:     s.options.Secret,
			Label:      DefaultSignatureLabel,
		})
}

func (s *Signer) SignResponse(resp *http.Response) error {
	baseParams, err := s.options.baseParameters(s.mdp)
	if err != nil {
		return err
	}

	return sign(
		httpMessage{
			IsResponse: true,
			Resp:       resp,
		}, sigParameters{
			Base:       baseParams,
			Algo:       s.options.Algorithm,
			PrivateKey: s.options.PrivateKey,
			Label:      DefaultSignatureLabel,
		})
}

// translation
func (sp SigningOptions) baseParameters(mdp MetadataProvider) (sigBaseInput, error) {
	bp := sigBaseInput{
		Components:     componentsIDs(sp.Fields),
		MetadataParams: sp.Metadata,
		MetadataValues: sp,
	}
	if mdp != nil {
		bp.MetadataValues = mdp
	}
	return bp, nil
}

func (so SigningOptions) validate() error {
	if so.Algorithm == "" {
		return fmt.Errorf("Missing required signing option 'Algorithm'")
	}
	if so.Algorithm.symmetric() {
		if len(so.Secret) == 0 {
			return newError(ErrInvalidSignatureOptions, "Missing required signing option 'Secret'")
		}
	} else {
		if so.PrivateKey == nil {
			return newError(ErrInvalidSignatureOptions, "Missing required signing option 'PrivateKey'")
		}
	}

	if !isSafeString(so.Label) {
		return fmt.Errorf("Invalid label name '%s'", so.Label)
	}
	for _, sf := range so.Fields {
		if !isSafeString(sf.Name) {
			return fmt.Errorf("Invalid signing field name '%s'", sf.Name)
		}
	}

	for _, md := range so.Metadata {
		switch md {
		case MetaKeyID:
			if so.MetaKeyID == "" {
				return fmt.Errorf("'keyid' metadata parameter was listed but missing MetaKeyID value'")
			}
			if !isSafeString(so.MetaKeyID) {
				return fmt.Errorf("'keyid' metadata parameter can only contain printable characters'")
			}
		case MetaTag:
			if so.MetaTag == "" {
				return fmt.Errorf("'tag' metadata parameter was listed but missing MetaTag value'")
			}
			if !isSafeString(so.MetaTag) {
				return fmt.Errorf("'tag' metadata parameter can only contain printable characters'")
			}
		}
	}
	return nil
}

func (so SigningOptions) withDefaults() SigningOptions {
	final := SigningOptions{
		PrivateKey:          so.PrivateKey,
		Secret:              so.Secret,
		Algorithm:           so.Algorithm,
		Digest:              so.Digest,
		Fields:              so.Fields,
		Metadata:            so.Metadata,
		Label:               so.Label,
		MetaKeyID:           so.MetaKeyID,
		MetaTag:             so.MetaTag,
		MetaExpiresDuration: so.MetaExpiresDuration,
		MetaNonce:           NonceRandom32,
	}
	// Defaults
	if final.Label == "" {
		final.Label = DefaultSignatureLabel
	}
	if final.MetaExpiresDuration == 0 {
		final.MetaExpiresDuration = time.Minute * 5
	}
	if final.Digest == "" {
		final.Digest = DigestSHA256
	}

	return final
}

func (sf SignedField) componentID() componentID {
	item := sfv.NewItem(sf.Name)
	for key, param := range sf.Parameters {
		item.Params.Add(key, param)
	}
	return componentID{
		Name: strings.ToLower(sf.Name),
		Item: item,
	}
}

func (a Algorithm) symmetric() bool {
	switch a {
	case Algo_HMAC_SHA256:
		return true
	}
	return false
}
func componentsIDs(sfs []SignedField) []componentID {
	cIDs := []componentID{}
	for _, sf := range sfs {
		cIDs = append(cIDs, sf.componentID())
	}

	return cIDs
}

func nonceRandom32() (string, error) {
	nonce := make([]byte, 32)
	n, err := rand.Read(nonce)
	if err != nil || n < 32 {
		return "", fmt.Errorf("could not generate nonce")
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

func isSafeString(s string) bool {
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}
