package httpsig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	sfv "github.com/dunglas/httpsfv"
)

// sigBaseInput is the required input to calculate the signature base
type sigBaseInput struct {
	Components     []componentID
	MetadataParams []Metadata // metadata parameters to add to the signature and their values
	MetadataValues MetadataProvider
}

type httpMessage struct {
	IsResponse bool
	Req        *http.Request
	Resp       *http.Response
}

func (hrr httpMessage) Headers() http.Header {
	if hrr.IsResponse {
		return hrr.Resp.Header
	}
	return hrr.Req.Header
}

func (hrr httpMessage) Body() io.ReadCloser {
	if hrr.IsResponse {
		return hrr.Resp.Body
	}
	return hrr.Req.Body
}

func (hrr httpMessage) SetBody(body io.ReadCloser) {
	if hrr.IsResponse {
		hrr.Resp.Body = body
		return
	}
	hrr.Req.Body = body
}

func (hrr httpMessage) Context() context.Context {
	if hrr.IsResponse {
		return context.Background()
	}
	return hrr.Req.Context()
}

func (hrr httpMessage) isDebug() bool {
	if dbgval, ok := hrr.Context().Value(ctxKeyAddDebug).(bool); ok {
		return dbgval
	}
	return false
}

/*
calculateSignatureBase calculates the 'signature base' - the data used as the input to signing or verifying
The signature base is an ASCII string containing the canonicalized HTTP message components covered by the signature.
*/
func calculateSignatureBase(msg httpMessage, bp sigBaseInput) (signatureBase, error) {
	signatureParams := sfv.InnerList{
		Items:  []sfv.Item{},
		Params: sfv.NewParams(),
	}
	componentNames := []string{}
	var base strings.Builder

	// Add all the required components
	for _, component := range bp.Components {
		name, err := component.signatureName()
		if err != nil {
			return signatureBase{}, err
		}
		if slices.Contains(componentNames, name) {
			return signatureBase{}, newError(ErrInvalidSignatureOptions, fmt.Sprintf("Repeated component name not allowed: '%s'", name))
		}
		componentNames = append(componentNames, name)
		signatureParams.Items = append(signatureParams.Items, component.Item)

		value, err := component.signatureValue(msg)
		if err != nil {
			return signatureBase{}, err
		}

		base.WriteString(fmt.Sprintf("%s: %s\n", name, value))
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
		signatureInput: signatureParams,
	}, nil
}

// componentID is the signature 'component identifier' as detailed in the specification.
type componentID struct {
	Name string   // canonical, lower case component name. The name is also the value of the Item.
	Item sfv.Item // The sfv representation of the component identifier. This contains the name and parameters.
}

// SignatureName is the components serialized name required by the signature.
func (cID componentID) signatureName() (string, error) {
	signame, err := sfv.Marshal(cID.Item)
	if err != nil {
		return "", newError(ErrInvalidComponent, fmt.Sprintf("Unable to serialize component identifier '%s'", cID.Name), err)
	}
	return signame, nil
}

// signatureValue is the components value required by the signature.
func (cID componentID) signatureValue(msg httpMessage) (string, error) {
	msg, err := cID.sourceMessage(msg)
	if err != nil {
		return "", err
	}
	val := ""
	if strings.HasPrefix(cID.Name, "@") {
		val, err = deriveComponentValue(msg, cID)
		if err != nil {
			return "", err
		}
	} else {
		values := msg.Headers().Values(cID.Name)
		if len(values) == 0 {
			return "", newError(ErrInvalidComponent, fmt.Sprintf("Message is missing required component '%s'", cID.Name))
		}
		if key, found := cID.Item.Params.Get("key"); found {
			return cID.dictionaryMemberValue(values, key)
		}
		// TODO Handle multi value
		if len(values) > 1 {
			return "", newError(ErrUnsupported, fmt.Sprintf("This library does yet support signatures for components/headers with multiple values: %s", cID.Name))
		}
		val = msg.Headers().Get(cID.Name)
	}
	return val, nil
}

// sourceMessage is the message the component value comes from. The 'req' parameter selects the request that the response answers (RFC 9421 Section 2.4).
func (cID componentID) sourceMessage(msg httpMessage) (httpMessage, error) {
	req, found := cID.Item.Params.Get("req")
	if !found {
		return msg, nil
	}
	if flag, ok := req.(bool); !ok || !flag {
		return httpMessage{}, newError(ErrInvalidComponent, fmt.Sprintf("The 'req' parameter of component '%s' must be true", cID.Name))
	}
	if !msg.IsResponse {
		return httpMessage{}, newError(ErrInvalidComponent, fmt.Sprintf("Component '%s' has the 'req' parameter but the message is a request", cID.Name))
	}
	if msg.Resp.Request == nil {
		return httpMessage{}, newError(ErrInvalidComponent, fmt.Sprintf("Component '%s' has the 'req' parameter but the response has no associated request", cID.Name))
	}
	return httpMessage{Req: msg.Resp.Request}, nil
}

// dictionaryMemberValue is the serialized member that the 'key' parameter names (RFC 9421 Section 2.1.2).
func (cID componentID) dictionaryMemberValue(values []string, key any) (string, error) {
	memberKey, ok := key.(string)
	if !ok {
		return "", newError(ErrInvalidComponent, fmt.Sprintf("The 'key' parameter of component '%s' must be a string", cID.Name))
	}
	dict, err := sfv.UnmarshalDictionary(values)
	if err != nil {
		return "", newError(ErrInvalidComponent, fmt.Sprintf("Component '%s' has the 'key' parameter but is not a Dictionary", cID.Name), err)
	}
	member, found := dict.Get(memberKey)
	if !found {
		return "", newError(ErrInvalidComponent, fmt.Sprintf("Dictionary '%s' has no member '%s'", cID.Name, memberKey))
	}
	val, err := sfv.Marshal(member)
	if err != nil {
		return "", newError(ErrInvalidComponent, fmt.Sprintf("Unable to serialize member '%s' of '%s'", memberKey, cID.Name), err)
	}
	return val, nil
}
func deriveComponentValue(r httpMessage, component componentID) (string, error) {
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
	return "", newError(ErrInvalidSignatureOptions, fmt.Sprintf("Unsupported derived component identifier for a response '%s'. Use the 'req' parameter for a request component.", component.Name))
}

func deriveComponentValueRequest(req *http.Request, component componentID) (string, error) {
	switch component.Name {
	case "@method":
		return req.Method, nil
	case "@target-uri":
		return deriveTargetURI(req), nil
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
			return "", newError(ErrInvalidSignatureOptions, "@query-param specified but missing 'name' parameter to indicate which parameter.")
		}
		paramName, ok := paramKey.(string)
		if !ok {
			return "", newError(ErrInvalidSignatureOptions, "@query-param specified but the 'name' parameter must be a string to indicate which parameter.")
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

// deriveTargetURI resolves to an absolute form as required by RFC 9110 and referenced by the http signatures spec.
// The target URI excludes the reference's fragment component, if any, since fragment identifiers are reserved for client-side processing
func deriveTargetURI(req *http.Request) string {
	scheme := "https"
	if req.TLS == nil {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s%s", scheme, req.Host, req.URL.RequestURI())
}
