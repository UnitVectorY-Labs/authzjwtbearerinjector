package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

const (
	rs256 = "RS256"
	jwt   = "JWT"
)

func SignLocalJWT(config Config, privateKey *rsa.PrivateKey, metadataClaims map[string]string) (string, error) {

	DebugLog("Generating JWT with metadata claims: %v", metadataClaims)

	header := map[string]string{
		"alg": rs256, // Only supporting RS256 for now
		"typ": jwt,
	}

	if config.PrivateKeyId != "" {
		header["kid"] = config.PrivateKeyId
	}

	headerBytes, _ := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Payload
	payload := map[string]interface{}{}

	// Use the config file claims first
	for k, v := range config.LocalToken {
		payload[k] = v

		// Log the claims
		DebugLog("Added Config File Claim: %s = %s", k, v)
	}

	// The metadata claims will overwrite the environment variables
	for k, v := range metadataClaims {
		payload[k] = v
		// Log the claims
		DebugLog("Added Metadata Claim: %s = %s", k, v)
	}

	// The iat and exp claims are always added to the payload
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(time.Hour).Unix() // Defaulting to industry standard of 1 hour

	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Signature
	dataToSign := encodedHeader + "." + encodedPayload
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		DebugLog("Error signing JWT: %v", err)
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Final JWT
	jwtToken := encodedHeader + "." + encodedPayload + "." + encodedSignature
	return jwtToken, nil
}
