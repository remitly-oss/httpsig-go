package httpsig

import (
	"fmt"

	sfv "github.com/dunglas/httpsfv"
)

type AcceptSigkeyParam string

const (
	SigkeyParamJKT  AcceptSigkeyParam = "jkt"
	SigkeyParamURI  AcceptSigkeyParam = "uri"
	SigkeyParamX509 AcceptSigkeyParam = "x509"
)

type AcceptSignature struct {
	Profile     SigningProfile
	MetaNonce   string            // 'nonce'
	MetaKeyID   string            // 'keyid'
	MetaTag     string            // 'tag' - No default. A value must be provided if the parameter is in Metadata.
	SigkeyParam AcceptSigkeyParam // 'sigkey' - key transport requirement from draft-hardt-httpbis-signature-key
}

func ParseAcceptSignature(acceptHeader string) (AcceptSignature, error) {
	as := AcceptSignature{}
	acceptDict, err := sfv.UnmarshalDictionary([]string{acceptHeader})
	if err != nil {
		return as, newError(ErrInvalidAcceptSignature, "Unable to parse Accept-Signature value", err)
	}
	profiles := acceptDict.Names()
	if len(profiles) == 0 {
		return as, newError(ErrMissingAcceptSignature, "No Accept-Signature value")
	}

	label := profiles[0]
	profileItems, _ := acceptDict.Get(label)
	profileList, isList := profileItems.(sfv.InnerList)
	if !isList {
		return as, newError(ErrInvalidAcceptSignature, "Unable to parse Accept-Signature value. Accept-Signature must be a dictionary.")
	}

	fields := []string{}
	for _, componentItem := range profileList.Items {
		field, ok := componentItem.Value.(string)
		if !ok {
			return as, newError(ErrInvalidAcceptSignature, fmt.Sprintf("Invalid signature component '%v', Components must be strings", componentItem.Value))

		}
		fields = append(fields, field)
	}
	as.Profile = SigningProfile{
		Fields:   Fields(fields...),
		Label:    label,
		Metadata: []Metadata{},
	}

	md := metadataProviderFromParams{profileList.Params}
	for _, meta := range profileList.Params.Names() {
		switch Metadata(meta) {
		case MetaNonce:
			as.Profile.Metadata = append(as.Profile.Metadata, Metadata(meta))
			as.MetaNonce, _ = md.Nonce()
		case MetaAlgorithm:
			as.Profile.Metadata = append(as.Profile.Metadata, Metadata(meta))
			alg, _ := md.Alg()
			as.Profile.Algorithm = Algorithm(alg)
		case MetaKeyID:
			as.Profile.Metadata = append(as.Profile.Metadata, Metadata(meta))
			as.MetaKeyID, _ = md.KeyID()
		case MetaTag:
			as.Profile.Metadata = append(as.Profile.Metadata, Metadata(meta))
			as.MetaTag, _ = md.Tag()
		default:
			if meta == "sigkey" {
				if v, ok := profileList.Params.Get("sigkey"); ok {
					switch val := v.(type) {
					case sfv.Token:
						as.SigkeyParam = AcceptSigkeyParam(val)
					case string:
						as.SigkeyParam = AcceptSigkeyParam(val)
					}
				}
			} else {
				as.Profile.Metadata = append(as.Profile.Metadata, Metadata(meta))
			}
		}
	}

	return as, nil

}
