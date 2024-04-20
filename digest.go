package httpsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"

	sfv "github.com/dunglas/httpsfv"
)

var emptySHA256 = sha256.Sum256([]byte{})
var emptySHA512 = sha512.Sum512([]byte{})

// digestBody reads the entire body to calculate the digest and returns a new io.ReaderCloser which can be set as the new request body.
func digestBody(digAlgo Digest, body io.ReadCloser) (digest []byte, newBody io.ReadCloser, err error) {
	// client GET requests have a nil body
	// received/server GET requests have a body but its NoBody
	if body == nil || body == http.NoBody {
		switch digAlgo {
		case DigestSHA256:
			digest = emptySHA256[:]
		case DigestSHA512:
			digest = emptySHA512[:]
		default:
			return nil, body, newError(ErrInvalidDigestAlgorithm, fmt.Sprintf("Unsupported digest algorithm '%s'", digAlgo))
		}
		return digest, body, err
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(body); err != nil {
		return nil, body, newError(ErrInvalidDigest, "Failed to read message body to calculate digest", err)
	}
	if err := body.Close(); err != nil {
		return nil, body, newError(ErrInvalidDigest, "Failed to close message body to calculate digest", err)
	}

	switch digAlgo {
	case DigestSHA256:
		d := sha256.Sum256(buf.Bytes())
		digest = d[:]
	case DigestSHA512:
		d := sha512.Sum512(buf.Bytes())
		digest = d[:]
	default:
		return nil, body, newError(ErrInvalidDigestAlgorithm, fmt.Sprintf("Unsupported digest algorithm '%s'", digAlgo))
	}

	return digest, io.NopCloser(bytes.NewReader(buf.Bytes())), err
}

func createDigestHeader(algo Digest, digest []byte) (string, error) {
	sfValue := sfv.NewItem(digest)
	header := sfv.NewDictionary()
	switch algo {
	case DigestSHA256:
		header.Add("sha-256", sfValue)
	case DigestSHA512:
		header.Add("sha-512", sfValue)
	default:
		return "", newError(ErrInvalidDigestAlgorithm, fmt.Sprintf("Unsupported digest algorithm '%s'", algo))
	}
	value, err := sfv.Marshal(header)
	if err != nil {
		return "", newError(ErrInvalidDigest, "Failed to marshal digest", err)
	}
	return value, nil

}

// getSupportedDigestFromHeader returns the first supported digest from the supplied header. If no supported header is found a nil digest is returned.
func getSupportedDigestFromHeader(contentDigestHeader []string) (algo Digest, digest []byte, err error) {
	digestDict, err := sfv.UnmarshalDictionary(contentDigestHeader)
	if err != nil {
		return "", nil, newError(ErrInvalidHeader, "Could not parse Content-Digest header", err)
	}

	for _, algo := range digestDict.Names() {
		switch Digest(algo) {
		case DigestSHA256:
			fallthrough
		case DigestSHA512:
			member, ok := digestDict.Get(algo)
			if !ok {
				continue
			}
			item, ok := member.(sfv.Item)
			if !ok {
				// If not a an Item it's not a valid header value. Skip
				continue
			}
			if digest, ok := item.Value.([]byte); ok {
				return Digest(algo), digest, nil
			}
		default:
			// Unsupported
			continue
		}
	}

	return "", nil, nil
}
