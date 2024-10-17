package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	config "authzjwtbearerinjector/internal/config"
	logger "authzjwtbearerinjector/internal/logger"
)

const (
	rs256 = "RS256"
	jwt   = "JWT"
)

func SignLocalJWT(config config.Config, privateKey *rsa.PrivateKey, metadataTokenHeader map[string]string, metadataTokenPayload map[string]string) (string, error) {

	// Build the Header
	header := map[string]string{}

	for k, v := range config.TokenHeader {
		header[k] = replaceDynamicVariables(v)
		logger.DebugLog("Added Header: %s = %s", k, v)
	}

	for k, v := range metadataTokenHeader {
		header[k] = replaceDynamicVariables(v)
		logger.DebugLog("Added Header (Metadata): %s = %s", k, v)
	}

	header["alg"] = rs256
	header["typ"] = jwt

	headerBytes, _ := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Build the Payload
	payload := map[string]interface{}{}

	for k, v := range config.TokenPayload {
		payload[k] = replaceDynamicVariables(v)
		logger.DebugLog("Added Payload Claim: %s = %s", k, v)
	}

	for k, v := range metadataTokenPayload {
		payload[k] = replaceDynamicVariables(v)
		logger.DebugLog("Added Payload Claim (Metadata): %s = %s", k, v)
	}

	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(time.Hour).Unix() // Defaulting to industry standard of 1 hour

	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create the signature
	dataToSign := encodedHeader + "." + encodedPayload
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		logger.DebugLog("Error signing JWT: %v", err)
		return "", err
	}

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Build the final JWT
	jwtToken := encodedHeader + "." + encodedPayload + "." + encodedSignature

	return jwtToken, nil
}

func replaceDynamicVariables(input string) string {
	if strings.Contains(input, "${{UUID}}") {
		return strings.ReplaceAll(input, "${{UUID}}", uuid.New().String())
	}
	return input
}
