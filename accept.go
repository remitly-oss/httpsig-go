package httpsig

import (
	"fmt"

	sfv "github.com/dunglas/httpsfv"
)

func ParseAcceptSignature(acceptHeader string) (SigningProfile, error) {
	acceptDict, err := sfv.UnmarshalDictionary([]string{acceptHeader})
	if err != nil {
		return SigningProfile{}, newError(ErrInvalidAcceptSignature, "Unable to parse Accept-Signature value", err)
	}
	profiles := acceptDict.Names()
	if len(profiles) == 0 {
		return SigningProfile{}, newError(ErrMissingAcceptSignature, "No Accept-Signature value")
	}

	label := profiles[0]
	profileItems, _ := acceptDict.Get(label)
	profileList, isList := profileItems.(sfv.InnerList)
	if !isList {
		return SigningProfile{}, newError(ErrInvalidAcceptSignature, "Unable to parse Accept-Signature value. Accept-Signature must be a dictionary.")
	}

	fields := []string{}
	for _, componentItem := range profileList.Items {
		field, ok := componentItem.Value.(string)
		if !ok {
			return SigningProfile{}, newError(ErrInvalidAcceptSignature, fmt.Sprintf("Invalid signature component '%v', Components must be strings", componentItem.Value))

		}
		fields = append(fields, field)
	}
	so := SigningProfile{
		Fields:   Fields(fields...),
		Label:    label,
		Metadata: []Metadata{},
	}

	md := metadataProviderFromParams{profileList.Params}
	for _, meta := range profileList.Params.Names() {
		so.Metadata = append(so.Metadata, Metadata(meta))
		switch Metadata(meta) {
		case MetaAlgorithm:
			alg, _ := md.Alg()
			so.Algorithm = Algorithm(alg)
		case MetaKeyID:
			so.MetaKeyID, _ = md.KeyID()
		case MetaTag:
			so.MetaTag, _ = md.Tag()
		}
	}

	return so, nil

}
