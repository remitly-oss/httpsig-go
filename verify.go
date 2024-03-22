package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"time"

	sfv "github.com/dunglas/httpsfv"
)

var (
	DefaultVerifyProfile = VerifyProfile{
		AllowedAlgorithms:  []Algorithm{Algo_ECDSA_P256_SHA256, Algo_ECDSA_P384_SHA384, Algo_ED25519, Algo_HMAC_SHA256},
		RequiredFields:     DefaultRequiredFields,
		RequiredMetadata:   []Metadata{MetaCreated, MetaKeyID},
		DisallowedMetadata: []Metadata{MetaAlgorithm}, // The algorithm should be looked up from the keyid not an explicit setting.

		CreatedValidDuration: time.Minute * 5, // Signatures must have been created within within the last 5 minutes
		DateFieldSkew:        time.Minute,     // If the created parameter is present, the Date header cannot be more than a minute off.
	}

	// DefaultRequiredFields covers the request body with 'content-digest' the method and full URI.
	// As per the specification Date is not covered in favor of using the 'created' metadata parameter.
	DefaultRequiredFields = Fields("content-digest", "@method", "@target-uri")
)

type KeySpec struct {
	KeyID  string
	Algo   Algorithm
	PubKey crypto.PublicKey
	Secret []byte // shared secret for symmetric algorithms
}

type KeyErrorReason string

type KeyError struct {
	error
	Reason  KeyErrorReason
	Message string
}

type KeyFetcher interface {
	// FetchByKeyID looks up a KeySpec from the 'keyid' metadata parameter on the signature.
	FetchByKeyID(keyID string) (KeySpec, error)
	// Fetch looks up a KeySpec when the is not a keyid in the signature.
	Fetch(rh http.Header, md MetadataProvider) (KeySpec, error)
}

// VerifyProfile sets the parameters for a fully valid request or response.
// A valid signature is a relatively easy accomplishment. Did the signature include of the request? Did it use a strong enough algorithm? Was it signed 41 days ago?  There are choices to make about what constitutes a valid signed request or response.
type VerifyProfile struct {
	RequiredFields     []SignedField
	RequiredMetadata   []Metadata
	DisallowedMetadata []Metadata
	AllowedAlgorithms  []Algorithm // Which algorithms are allowed, either from keyid meta or in the KeySpec

	// Timing enforcement options
	DisableTimeEnforcement       bool          // If true do no time enforcement on any fields
	DisableExpirationEnforcement bool          // If expiration is present default to enforce
	CreatedValidDuration         time.Duration // Duration allowed for between time.Now and the created time
	ExpiredSkew                  time.Duration // Maximum duration allowed between time.Now and the expired time
	DateFieldSkew                time.Duration // Maximum duration allowed between Date field and created

}

type VerifiedSignature struct {
	Label    string // Label should not be used for the identity of the caller. Use keyid or tag instead. Label can be set by an attacker.
	Metadata MetadataProvider
}

type VerifyResult struct {
	Signatures []VerifiedSignature
}

// KeyID returns the key id of the signature. An error is returned if there is more than one signature.
func (vr VerifyResult) KeyID() (string, error) {
	if len(vr.Signatures) > 1 {
		return "", fmt.Errorf("Multiple signatures present")
	}
	return vr.Signatures[0].Metadata.KeyID()
}

type Verifier struct {
	keys    KeyFetcher
	profile VerifyProfile
}

// Verify validates the signatures in a request and ensured the signature meets the required profile.
func Verify(req *http.Request, kf KeyFetcher, profile VerifyProfile) (VerifyResult, error) {
	ver, err := NewVerifier(kf, profile)
	if err != nil {
		return VerifyResult{}, err
	}
	return ver.Verify(req)
}

func VerifyResponse(resp *http.Response, kf KeyFetcher, profile VerifyProfile) (VerifyResult, error) {
	ver, err := NewVerifier(kf, profile)
	if err != nil {
		return VerifyResult{}, err
	}
	return ver.VerifyResponse(resp)
}

func NewVerifier(kf KeyFetcher, profile VerifyProfile) (*Verifier, error) {
	return &Verifier{
		keys: kf,
	}, nil
}

func (ver *Verifier) Verify(req *http.Request) (VerifyResult, error) {
	return ver.verify(httpMessage{
		Req: req,
	})
}

func (ver *Verifier) VerifyResponse(resp *http.Response) (VerifyResult, error) {
	return ver.verify(httpMessage{
		IsResponse: true,
		Resp:       resp,
	})
}

func (ver *Verifier) verify(hrr httpMessage) (VerifyResult, error) {
	vres := VerifyResult{
		Signatures: []VerifiedSignature{},
	}

	/* extract signatures */
	sigs, err := extractSignatures(hrr.Headers())
	if err != nil {
		return vres, err
	}

	if len(sigs.sigs) == 0 {
		return vres, newError(ErrMissingSignature, "No signatures found in request")
	}

	/* verify signatures */
	for _, sig := range sigs.sigs {
		err := ver.verifySignature(hrr, sig)
		if err != nil {
			return vres, err
		}
		/* validate against profile */
		ver.profile.validate(sig)
		vres.Signatures = append(vres.Signatures, VerifiedSignature{
			Label:    sig.Label,
			Metadata: sig.Input.MetadataValues,
		})
	}

	return vres, nil
}

type extractedSignatures struct {
	sigs              []extractedSignature
	invalidSignatures map[string]error // map[signature label]reason
}

type extractedSignature struct {
	Label     string
	Signature []byte
	Input     sigBaseInput
}

func extractSignatures(headers http.Header) (extractedSignatures, error) {
	extracted := extractedSignatures{
		sigs:              []extractedSignature{},
		invalidSignatures: map[string]error{},
	}
	/* Pull signature and signature-input header */
	sigHeader := headers.Get("signature")
	if sigHeader == "" {
		return extracted, newError(ErrMissingSignature, "Missing signature header")
	}
	sigInputHeader := headers.Get("signature-input")
	if sigInputHeader == "" {
		return extracted, newError(ErrMissingSignature, "Missing signature-input header")
	}

	/* Parse headers into their appropriate HTTP structured field values */
	// signature-input must be a HTTP structured field value of type Dictionary.
	sigInputDict, err := sfv.UnmarshalDictionary([]string{sigInputHeader})
	if err != nil {
		return extracted, newError(ErrInvalidSignature, "Invalid signature-input header. Not a valid Dictionary", err)
	}
	// signature must be a HTTP structured field value of type Dictionary.
	sigDict, err := sfv.UnmarshalDictionary([]string{sigHeader})
	if err != nil {
		return extracted, newError(ErrInvalidSignature, "Invalid signature header. Not a valid Dictionary", err)
	}

	/* Process each signature  */
	// Iterate through each signature
	for _, sigLabel := range sigDict.Names() {
		sigInfo := extractedSignature{
			Label: sigLabel,
		}

		sigMember, _ := sigDict.Get(sigLabel)

		// The signature must be of sfv type 'Item'
		sigItem, isItem := sigMember.(sfv.Item)
		if !isItem {
			extracted.invalidSignatures[sigLabel] = fmt.Errorf("The signature for label '%s' must be type Item. It was type %T", sigLabel, sigMember)
			continue
		}
		// Signatures must be byte sequences. The sfv library uses []byte for byte sequences.
		sigBytes, isByteSequence := sigItem.Value.([]byte)
		if !isByteSequence {
			extracted.invalidSignatures[sigLabel] = fmt.Errorf("The signature for label '%s' was not a byte sequence. It was type %T", sigLabel, sigItem.Value)
			continue
		}
		sigInfo.Signature = sigBytes

		// Grab the corresponding signature input
		sigInputMember, hasInput := sigInputDict.Get(sigLabel)
		if !hasInput {
			extracted.invalidSignatures[sigLabel] = fmt.Errorf("The signature-input for label '%s' is not present", sigLabel)
			continue
		}

		// The signature input must be of sfv type InnerList
		sigInputList, isList := sigInputMember.(sfv.InnerList)
		if !isList {
			extracted.invalidSignatures[sigLabel] = fmt.Errorf("The signature-input for label '%s' must be type InnerList. It was type '%T'.", sigLabel, sigInputMember)
			continue
		}
		cIDs := []componentID{}
		for _, componentItem := range sigInputList.Items {
			name, ok := componentItem.Value.(string)
			if !ok {
				extracted.invalidSignatures[sigLabel] = fmt.Errorf("signature components must be string types")
				continue
			}
			cIDs = append(cIDs, componentID{
				Name: name,
				Item: componentItem,
			})
		}
		mds := []Metadata{}
		for _, name := range sigInputList.Params.Names() {
			mds = append(mds, Metadata(name))
		}
		sigInfo.Input = sigBaseInput{
			Components:     cIDs,
			MetadataParams: mds,
			MetadataValues: metadataProviderFromParams{sigInputList.Params},
		}
		extracted.sigs = append(extracted.sigs, sigInfo)
	}

	return extracted, nil
}

func (ver *Verifier) verifySignature(r httpMessage, sig extractedSignature) error {
	base, err := calculateSignatureBase(r, sig.Input)
	if err != nil {
		return err
	}

	var ks KeySpec
	if slices.Contains(sig.Input.MetadataParams, MetaKeyID) {
		keyid, err := sig.Input.MetadataValues.KeyID()
		if err != nil {
			return err
		}
		ks, err = ver.keys.FetchByKeyID(keyid)
		if err != nil {
			return newError(ErrKeyFetch, fmt.Sprintf("Failed to fetch key for keyid '%s'\n", keyid), err)
		}
	} else {
		ks, err = ver.keys.Fetch(r.Headers(), sig.Input.MetadataValues)
		if err != nil {
			return newError(ErrKeyFetch, fmt.Sprintf("Failed to fetch key for signature without a keyid and with label '%s'\n", sig.Label), err)
		}
	}

	switch ks.Algo {
	case Algo_RSA_PSS_SHA512:
		if rsapub, ok := ks.PubKey.(*rsa.PublicKey); ok {
			opts := &rsa.PSSOptions{
				SaltLength: 64,
				Hash:       crypto.SHA512,
			}
			msgHash := sha512.Sum512(base.base)
			err := rsa.VerifyPSS(rsapub, crypto.SHA512, msgHash[:], sig.Signature, opts)
			if err != nil {
				return newError(ErrVerification, fmt.Sprintf("Signature did not verify for algo '%s'", ks.Algo), err)
			}
			return nil
		} else {
			return newError(ErrInvalidPublicKey, fmt.Sprintf("Invalid public key. Requires rsa.PublicKey but got type: %T", ks.PubKey))
		}
	case Algo_RSA_v1_5_sha256:
		if rsapub, ok := ks.PubKey.(*rsa.PublicKey); ok {
			msgHash := sha256.Sum256(base.base)
			err := rsa.VerifyPKCS1v15(rsapub, crypto.SHA256, msgHash[:], sig.Signature)
			if err != nil {
				return newError(ErrVerification, fmt.Sprintf("Signature did not verify for algo '%s'", ks.Algo), err)
			}
			return nil
		} else {
			return newError(ErrInvalidPublicKey, fmt.Sprintf("Invalid public key. Requires rsa.PublicKey but got type: %T", ks.PubKey))
		}
	case Algo_HMAC_SHA256:
		msgHash := hmac.New(sha256.New, ks.Secret)
		msgHash.Write(base.base) // write does not return an error per hash.Hash documentation
		calcualtedSignature := msgHash.Sum(nil)
		if !hmac.Equal(calcualtedSignature, sig.Signature) {
			return newError(ErrVerification, fmt.Sprintf("Signature did not verify for algo '%s'", ks.Algo), err)
		}
	case Algo_ECDSA_P256_SHA256:
		if epub, ok := ks.PubKey.(*ecdsa.PublicKey); ok {
			if len(sig.Signature) != 64 {
				return newError(ErrInvalidSignature, fmt.Sprintf("Signature must be 64 bytes for algorithm '%s'", Algo_ECDSA_P256_SHA256))
			}
			msgHash := sha256.Sum256(base.base)
			// Concatenate r and s to form the signature as per the spec. r and s and *not* ANS1 encoded.
			r := new(big.Int)
			r.SetBytes(sig.Signature[0:32])
			s := new(big.Int)
			s.SetBytes(sig.Signature[32:64])
			if !ecdsa.Verify(epub, msgHash[:], r, s) {
				return newError(ErrVerification, fmt.Sprintf("Signature did not verify for algo '%s'", ks.Algo), err)
			}
		} else {
			return newError(ErrInvalidPublicKey, fmt.Sprintf("Invalid public key. Requires *ecdsa.PublicKey but got type: %T", ks.PubKey))
		}
	case Algo_ED25519:
		if edpubkey, ok := ks.PubKey.(ed25519.PublicKey); ok {
			if !ed25519.Verify(edpubkey, base.base, sig.Signature) {
				return newError(ErrVerification, fmt.Sprintf("Signature did not verify for algo '%s'", ks.Algo), err)
			}
		}
	default:
		return newError(ErrInvalidAlgorithm, fmt.Sprintf("Invalid verification algorithm '%s'", ks.Algo))
	}
	return nil
}

func (vp VerifyProfile) validate(sig extractedSignature) error {
	return nil
}

type metadataProviderFromParams struct {
	Params *sfv.Params
}

func (mp metadataProviderFromParams) Created() (int, error) {
	if val, ok := mp.Params.Get(string(MetaCreated)); ok {
		return int(val.(int64)), nil
	}
	return 0, fmt.Errorf("No created value")
}

func (mp metadataProviderFromParams) Expires() (int, error) {
	if val, ok := mp.Params.Get(string(MetaExpires)); ok {
		return int(val.(int64)), nil
	}
	return 0, fmt.Errorf("No expires value")
}

func (mp metadataProviderFromParams) Nonce() (string, error) {
	if val, ok := mp.Params.Get(string(MetaNonce)); ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No nonce value")
}

func (mp metadataProviderFromParams) Alg() (string, error) {
	if val, ok := mp.Params.Get(string(MetaAlgorithm)); ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No alg value")
}

func (mp metadataProviderFromParams) KeyID() (string, error) {
	if val, ok := mp.Params.Get(string(MetaKeyID)); ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No keyid value")
}

func (mp metadataProviderFromParams) Tag() (string, error) {
	if val, ok := mp.Params.Get(string(MetaTag)); ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("No tag value")
}
