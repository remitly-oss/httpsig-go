package httpsig

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"testing"
)

func TestDigestCreate(t *testing.T) {
	testcases := []struct {
		Name            string
		Algo            Digest
		Body            io.ReadCloser
		ExpectedDigest  string // base64 encoded digest
		ExpectedHeader  string
		ExpectedErrCode ErrCode
	}{
		{
			Name:           "sha-256",
			Algo:           DigestSHA256,
			Body:           makeBody("hello world"),
			ExpectedDigest: "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
			ExpectedHeader: "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:",
		},
		{
			Name:           "sha-512",
			Algo:           DigestSHA512,
			Body:           makeBody("hello world"),
			ExpectedDigest: "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==",
			ExpectedHeader: "sha-512=:MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==:",
		},
		{
			Name:            "UnsupportedAlgorithm",
			Algo:            Digest("nope"),
			Body:            makeBody("hello world"),
			ExpectedErrCode: ErrInvalidDigestAlgorithm,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			actual, _, err := digestBody(tc.Algo, tc.Body)
			if err != nil {
				if tc.ExpectedErrCode != "" {
					diffErrorCode(t, err, tc.ExpectedErrCode)
					return
				}
				t.Fatal(err)
			}
			actualEncoded := base64.StdEncoding.EncodeToString(actual)
			Diff(t, tc.ExpectedDigest, actualEncoded, "Wrong digest")

			actualHeader, err := createDigestHeader(tc.Algo, actual)
			if err != nil {
				t.Fatal(err)
			}
			Diff(t, tc.ExpectedHeader, actualHeader, "Wrong digest header")
		})
	}
}

func TestDigestParse(t *testing.T) {
	testcases := []struct {
		Name            string
		Header          []string
		ExcepctedAlgo   Digest
		ExpectedDigest  string // base64 encoded digest
		ExpectedErrCode ErrCode
	}{
		{
			Name:           "sha-256",
			Header:         []string{"sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:"},
			ExcepctedAlgo:  DigestSHA256,
			ExpectedDigest: "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
		},
		{
			Name:           "sha-512",
			Header:         []string{"sha-512=:MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==:"},
			ExcepctedAlgo:  DigestSHA512,
			ExpectedDigest: "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==",
		},
		{
			Name:           "Empty",
			Header:         []string{},
			ExpectedDigest: "",
		},
		{
			Name:            "BadHeader",
			Header:          []string{"bl===ah"},
			ExpectedErrCode: ErrInvalidHeader,
		},
		{
			Name:           "Unsupported",
			Header:         []string{"md5=:blah:"},
			ExpectedDigest: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			actualAlgo, actualDigest, err := getSupportedDigestFromHeader(tc.Header)
			if err != nil {
				if tc.ExpectedErrCode != "" {
					diffErrorCode(t, err, tc.ExpectedErrCode)
					return
				}
				t.Fatal(err)
			} else if tc.ExpectedErrCode != "" {
				t.Fatal("Expected an err")
			}
			digestEncoded := base64.StdEncoding.EncodeToString(actualDigest)
			Diff(t, tc.ExcepctedAlgo, actualAlgo, "Wrong digest algo")
			Diff(t, tc.ExpectedDigest, digestEncoded, "Wrong digest")
		})
	}
}

func makeBody(body string) io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte(body)))
}

func diffErrorCode(t *testing.T, err error, code ErrCode) bool {
	var sigerr *SignatureError
	if errors.As(err, &sigerr) {
		return Diff(t, code, sigerr.Code, "Wrong error code")
	}
	return false
}
