package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log"
	"strings"
)

var (
	pemKeyReplacer strings.Replacer
)

func init() {
	pemKeyReplacer = *strings.NewReplacer(
		"-----BEGIN PRIVATE KEY-----", "",
		"-----END PRIVATE KEY-----", "",
		"\\n", "",
		"\n", "",
	)
}

func ParsePrivateKey(privateKeyString string) (*rsa.PrivateKey, error) {
	// Remove the PEM header, footer, and any newlines so we can decode the key
	privateKeyCleaned := pemKeyReplacer.Replace(privateKeyString)
	privateKeyCleaned = strings.TrimSpace(privateKeyCleaned)

	// Decode the Base64-encoded private key
	decodedKey, err := base64.StdEncoding.DecodeString(privateKeyCleaned)
	if err != nil {
		log.Printf("failed to base64 decode private key: %v", err)
		return nil, err
	}

	// Parse the PKCS#8 private key
	parsedKey, err := x509.ParsePKCS8PrivateKey(decodedKey)
	if err != nil {
		log.Printf("failed to parse PKCS#8 private key: %v", err)
		return nil, err
	}

	// Ensure the key is of type *rsa.PrivateKey
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Println("not an RSA private key")
		return nil, errors.New("not an RSA private key")
	}

	log.Println("Successfully parsed the RSA private key")
	return privateKey, nil
}
