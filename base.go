package httpsig

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	sfv "github.com/dunglas/httpsfv"
)

// componentID is the signature 'component identifier' as detailed in the specification.
type componentID struct {
	Name string   // canonical, lower case component name. The name is also the value of the Item.
	Item sfv.Item // The sfv representation of the component identifier. This contains the name and parameters.
}

// sigBaseInput is the required input to calculate the signature base
type sigBaseInput struct {
	Components     []componentID
	MetadataParams []Metadata // metadata parameters to add to the signature and their values
	MetadataValues MetadataProvider
}

type httpReqResp struct {
	IsResponse bool
	Req        *http.Request
	Resp       *http.Response
}

func (hrr httpReqResp) Headers() http.Header {
	if hrr.IsResponse {
		return hrr.Resp.Header
	}
	return hrr.Req.Header
}

/*
calculateSignatureBase calculates the 'signature base' - the data used as the input to signing or verifying
The signature base is an ASCII string containing the canonicalized HTTP message components covered by the signature.
*/
func calculateSignatureBase(r httpReqResp, bp sigBaseInput) (signatureBase, error) {
	signatureParams := sfv.InnerList{
		Items:  []sfv.Item{},
		Params: sfv.NewParams(),
	}
	componentNames := []string{}
	var base strings.Builder

	// Add all the required components
	for _, component := range bp.Components {
		/* Get component name */
		// The serialized component name is the sfv StringItem which may contain parameters. This is also the unique key.
		name, err := sfv.Marshal(component.Item)
		if err != nil {
			return signatureBase{}, newError(ErrInvalidComponent, fmt.Sprintf("Unable to serialize component identifier '%s'", component.Name), err)
		}
		if slices.Contains(componentNames, name) {
			return signatureBase{}, newError(ErrInvalidSignatureOptions, fmt.Sprintf("Repeated component name not allowed: '%s'", name))
		}
		signatureParams.Items = append(signatureParams.Items, component.Item)
		componentNames = append(componentNames, name)

		/* Get component value */
		// TODO Handle parameters
		var componentValue string
		if strings.HasPrefix(component.Name, "@") {
			componentValue, err = deriveComponentValue(r, component)
			if err != nil {
				return signatureBase{}, err
			}
		} else {
			values := r.Headers().Values(component.Name)
			// TODO Handle multi value
			if len(values) > 1 {
				return signatureBase{}, newError(ErrUnsupported, fmt.Sprintf("This library does yet support signatures for components/headers with multiple values: %s", component.Name))
			}
			componentValue = r.Headers().Get(component.Name)
		}

		base.WriteString(fmt.Sprintf("%s: %s\n", name, componentValue))
	}

	// Add signature metadata parameters
	for _, meta := range bp.MetadataParams {
		switch meta {
		case MetaCreated:
			created, err := bp.MetadataValues.Created()
			if err != nil {
				return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Failed to get value for %s metadata parameter", meta), err)
			}
			signatureParams.Params.Add(string(MetaCreated), created)
		case MetaExpires:
			expires, err := bp.MetadataValues.Expires()
			if err != nil {
				return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Failed to get value for %s metadata parameter", meta), err)
			}
			signatureParams.Params.Add(string(MetaExpires), expires)
		case MetaNonce:
			nonce, err := bp.MetadataValues.Nonce()
			if err != nil {
				return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Failed to get value for %s metadata parameter", meta), err)
			}
			signatureParams.Params.Add(string(MetaNonce), nonce)
		case MetaAlgorithm:
			alg, err := bp.MetadataValues.Alg()
			if err != nil {
				return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Failed to get value for %s metadata parameter", meta), err)
			}
			signatureParams.Params.Add(string(MetaAlgorithm), alg)
		case MetaKeyID:
			keyID, err := bp.MetadataValues.KeyID()
			if err != nil {
				return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Failed to get value for %s metadata parameter", meta), err)
			}
			signatureParams.Params.Add(string(MetaKeyID), keyID)
		case MetaTag:
			tag, err := bp.MetadataValues.Tag()
			if err != nil {
				return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Failed to get value for %s metadata parameter", meta), err)
			}
			signatureParams.Params.Add(string(MetaTag), tag)
		default:
			return signatureBase{}, newError(ErrInvalidMetadata, fmt.Sprintf("Invalid metadata field '%s'", meta))
		}
	}

	paramsOut, err := sfv.Marshal(signatureParams)
	if err != nil {
		return signatureBase{}, fmt.Errorf("Failed to marshal params: %w", err)
	}

	base.WriteString(fmt.Sprintf("\"%s\": %s", sigparams, paramsOut))
	return signatureBase{
		base:           []byte(base.String()),
		signatureInput: paramsOut,
	}, nil
}

func deriveComponentValue(r httpReqResp, component componentID) (string, error) {
	if r.IsResponse {
		return deriveComponentValueResponse(r.Resp, component)
	}
	return deriveComponentValueRequest(r.Req, component)
}

func deriveComponentValueResponse(resp *http.Response, component componentID) (string, error) {
	switch component.Name {
	case "@status":
		return strconv.Itoa(resp.StatusCode), nil
	}
	return "", nil
}

func deriveComponentValueRequest(req *http.Request, component componentID) (string, error) {
	switch component.Name {
	case "@method":
		return req.Method, nil
	case "@target-uri":
		return req.RequestURI, nil
	case "@authority":
		return req.Host, nil
	case "@scheme":
	case "@request-target":
	case "@path":
		return req.URL.Path, nil
	case "@query":
		return fmt.Sprintf("?%s", req.URL.RawQuery), nil
	case "@query-param":
		paramKey, found := component.Item.Params.Get("name")
		if !found {
			return "", newError(ErrInvalidSignatureOptions, fmt.Sprintf("@query-param specified but missing 'name' parameter to indicate which parameter."))
		}
		paramName, ok := paramKey.(string)
		if !ok {
			return "", newError(ErrInvalidSignatureOptions, fmt.Sprintf("@query-param specified but the 'name' parameter must be a string to indicate which parameter."))
		}
		paramValue := req.URL.Query().Get(paramName)
		// TODO support empty - is this still a string with a space in it?
		if paramValue == "" {
			return "", newError(ErrInvalidSignatureOptions, fmt.Sprintf("@query-param '%s' specified but that query param is not in the request", paramName))
		}
		return paramValue, nil
	default:
		return "", newError(ErrInvalidSignatureOptions, fmt.Sprintf("Unsupported derived component identifier for a request '%s'", component.Name))
	}
	return "", nil
}
