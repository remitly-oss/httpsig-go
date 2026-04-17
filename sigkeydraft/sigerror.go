package sigkeydraft

import (
	"fmt"
	"net/http"

	sfv "github.com/dunglas/httpsfv"
)

// SignatureErrorCode is a token value for the Signature-Error response header.
type SignatureErrorCode string

const (
	// SignatureErrorHeader is the canonical name of the Signature-Error HTTP response header.
	SignatureErrorHeader = "Signature-Error"

	ErrCodeUnsupportedAlgorithm SignatureErrorCode = "unsupported_algorithm"
	ErrCodeInvalidSignature     SignatureErrorCode = "invalid_signature"
	ErrCodeInvalidInput         SignatureErrorCode = "invalid_input"
	ErrCodeInvalidRequest       SignatureErrorCode = "invalid_request"
	ErrCodeInvalidKey           SignatureErrorCode = "invalid_key"
	ErrCodeUnknownKey           SignatureErrorCode = "unknown_key"
	ErrCodeInvalidJWT           SignatureErrorCode = "invalid_jwt"
	ErrCodeExpiredJWT           SignatureErrorCode = "expired_jwt"
)

// SignatureError represents a parsed Signature-Error response header.
type SignatureError struct {
	// Code is the required error token.
	Code SignatureErrorCode
	// SupportedAlgorithms is populated for ErrCodeUnsupportedAlgorithm errors.
	SupportedAlgorithms []string
	// RequiredInput is optionally populated for ErrCodeInvalidInput errors.
	RequiredInput []string
}

// ParseSignatureError parses the value of a Signature-Error response header.
func ParseSignatureError(headerValue string) (SignatureError, error) {
	dict, err := sfv.UnmarshalDictionary([]string{headerValue})
	if err != nil {
		return SignatureError{}, fmt.Errorf("sigkey: failed to parse Signature-Error header: %w", err)
	}

	member, ok := dict.Get("error")
	if !ok {
		return SignatureError{}, fmt.Errorf("sigkey: Signature-Error header missing required 'error' member")
	}

	item, ok := member.(sfv.Item)
	if !ok {
		return SignatureError{}, fmt.Errorf("sigkey: Signature-Error 'error' member must be an Item, got %T", member)
	}

	tok, ok := item.Value.(sfv.Token)
	if !ok {
		return SignatureError{}, fmt.Errorf("sigkey: Signature-Error 'error' value must be a token, got %T", item.Value)
	}

	se := SignatureError{Code: SignatureErrorCode(tok)}

	if m, ok2 := dict.Get("supported_algorithms"); ok2 {
		il, ok3 := m.(sfv.InnerList)
		if !ok3 {
			return SignatureError{}, fmt.Errorf("sigkey: Signature-Error 'supported_algorithms' must be an Inner List")
		}
		for _, algItem := range il.Items {
			s, ok4 := algItem.Value.(string)
			if !ok4 {
				return SignatureError{}, fmt.Errorf("sigkey: Signature-Error 'supported_algorithms' contains non-string item")
			}
			se.SupportedAlgorithms = append(se.SupportedAlgorithms, s)
		}
	}

	if m, ok2 := dict.Get("required_input"); ok2 {
		il, ok3 := m.(sfv.InnerList)
		if !ok3 {
			return SignatureError{}, fmt.Errorf("sigkey: Signature-Error 'required_input' must be an Inner List")
		}
		for _, inputItem := range il.Items {
			s, ok4 := inputItem.Value.(string)
			if !ok4 {
				return SignatureError{}, fmt.Errorf("sigkey: Signature-Error 'required_input' contains non-string item")
			}
			se.RequiredInput = append(se.RequiredInput, s)
		}
	}

	return se, nil
}

// SetSignatureError sets the Signature-Error response header on h.
func SetSignatureError(h http.Header, se SignatureError) error {
	dict := sfv.NewDictionary()
	dict.Add("error", sfv.NewItem(sfv.Token(se.Code)))

	if len(se.SupportedAlgorithms) > 0 {
		il := sfv.InnerList{Params: sfv.NewParams()}
		for _, alg := range se.SupportedAlgorithms {
			il.Items = append(il.Items, sfv.NewItem(alg))
		}
		dict.Add("supported_algorithms", il)
	}

	if len(se.RequiredInput) > 0 {
		il := sfv.InnerList{Params: sfv.NewParams()}
		for _, inp := range se.RequiredInput {
			il.Items = append(il.Items, sfv.NewItem(inp))
		}
		dict.Add("required_input", il)
	}

	value, err := sfv.Marshal(dict)
	if err != nil {
		return fmt.Errorf("sigkey: failed to marshal Signature-Error header: %w", err)
	}
	h.Set(SignatureErrorHeader, value)
	return nil
}
