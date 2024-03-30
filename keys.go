package httpsig

/*
const (
	// Hints for reading key
	PKCS1        string = "pkcs1"
	PKCS8        string = "pkcs8"
	PKCS8_RSAPSS string = "pkcs8_rsapss" // Go doesn't support
	ECC          string = "ecc"
	PKIX         string = "pxix"
)

var (
	rsapssAlgorithmIdentifier asn1.ObjectIdentifier
)

func init() {
	encodedRSAPSSID := "BgkqhkiG9w0BAQo=" // the base64 encoded asn1 algorithm identifier for RSA-PSS
	idBytes, err := base64.StdEncoding.DecodeString(encodedRSAPSSID)
	if err != nil {
		panic(fmt.Errorf("Failed to base64 decode encoded RSA PSS asn1 identifier: %w", err))
	}

	_, err = asn1.Unmarshal(idBytes, &rsapssAlgorithmIdentifier)
	if err != nil {
		panic(fmt.Errorf("Failed to unmarshal RSA PSS asn1 identifier: %w", err))
	}
}

// ReadPublicKey decodes a PEM encoded public key and parses into crypto.PublicKey
func ReadPublicKey(encodedPubkey []byte, hint ...string) (crypto.PublicKey, error) {
	block, _ := pem.Decode(encodedPubkey)
	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode public key")
	}
	var key crypto.PublicKey
	var err error

	format := PKIX // PKIX handles all supported algorithms. However older keys may encoded in another format.
	if len(hint) > 0 {
		format = hint[0]
	}

	switch format {
	case PKIX:
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
<<<<<<< Updated upstream
	case PKCS1:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
=======

		if err != nil {
			return nil, fmt.Errorf("Failed to parse public key with PKIX: %w", err)
		}
>>>>>>> Stashed changes
	default:
		return nil, fmt.Errorf("Unsupported public key format '%s'", format)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key with format %s: %w", format, err)
	}

	return key, nil
}

// ReadPrivateKey decodes a PEM encoded private key and parses into a crypto.PrivateKey
func ReadPrivateKey(encodedPrivateKey []byte, hint ...string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(encodedPrivateKey)

	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode private key")
	}

	var key crypto.PrivateKey
	var err error

	format := PKCS8 // PCKS8 handles all support algorithms. However older keys may be encoded in another format.
	if len(hint) > 0 {
		format = hint[0]
	}
	switch format {
	case PKCS8:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case PKCS1:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case ECC:
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case PKCS8_RSAPSS:
		// The rsa-pss key is PKCS8 encoded but the golang 1.12 parser doesn't recoganize the algorithm and gives 'PKCS#8 wrapping contained private key with unknown algorithm: 1.2.840.113549.1.1.10
		// Instead do the asn1 unmarshaling and check here.
		pkcs8 := struct {
			Version    int
			Algo       pkix.AlgorithmIdentifier
			PrivateKey []byte
		}{}

		_, err := asn1.Unmarshal(block.Bytes, &pkcs8)
		if err != nil {
			return nil, fmt.Errorf("Failed to ans1 unmarshal private key: %w", err)
		}
		if !pkcs8.Algo.Algorithm.Equal(rsapssAlgorithmIdentifier) {
			return nil, fmt.Errorf("PKCS#8 wrapping contained private key with unknown algorithm: %s", pkcs8.Algo.Algorithm)
		}

		key, err = x509.ParsePKCS1PrivateKey(pkcs8.PrivateKey)
	default:
		return nil, fmt.Errorf("Unsupported private key format '%s'", format)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key with format '%s': %w", format, err)
	}

	return key, nil
}
*/
