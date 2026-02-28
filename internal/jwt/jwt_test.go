package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	config "github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/config"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func TestSignLocalJWT_BasicStructure(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader:  map[string]string{},
		TokenPayload: map[string]string{},
	}

	jwt, err := SignLocalJWT(cfg, key, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT, got: %d", len(parts))
	}

	// Verify header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("failed to parse header: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got: %s", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got: %s", header["typ"])
	}

	// Verify payload has iat and exp
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("expected iat claim in payload")
	}
	if _, ok := payload["exp"]; !ok {
		t.Error("expected exp claim in payload")
	}
}

func TestSignLocalJWT_CustomClaims(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader: map[string]string{
			"kid": "test-key-id",
		},
		TokenPayload: map[string]string{
			"iss": "https://issuer.example.com",
			"sub": "https://subject.example.com",
			"aud": "https://audience.example.com",
		},
	}

	jwt, err := SignLocalJWT(cfg, key, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	parts := strings.Split(jwt, ".")

	// Verify custom header claims
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)
	if header["kid"] != "test-key-id" {
		t.Errorf("expected kid=test-key-id, got: %s", header["kid"])
	}

	// Verify custom payload claims
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadBytes, &payload)
	if payload["iss"] != "https://issuer.example.com" {
		t.Errorf("expected iss claim, got: %v", payload["iss"])
	}
	if payload["sub"] != "https://subject.example.com" {
		t.Errorf("expected sub claim, got: %v", payload["sub"])
	}
	if payload["aud"] != "https://audience.example.com" {
		t.Errorf("expected aud claim, got: %v", payload["aud"])
	}
}

func TestSignLocalJWT_MetadataOverrides(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader: map[string]string{
			"kid": "config-kid",
		},
		TokenPayload: map[string]string{
			"iss": "config-issuer",
		},
	}

	metadataHeader := map[string]string{
		"kid": "metadata-kid",
	}
	metadataPayload := map[string]string{
		"aud": "metadata-audience",
	}

	jwt, err := SignLocalJWT(cfg, key, metadataHeader, metadataPayload)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	parts := strings.Split(jwt, ".")

	// Verify header - metadata should override config for 'kid'
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)
	if header["kid"] != "metadata-kid" {
		t.Errorf("expected kid=metadata-kid (metadata override), got: %s", header["kid"])
	}

	// Verify payload - metadata adds 'aud' alongside config's 'iss'
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadBytes, &payload)
	if payload["aud"] != "metadata-audience" {
		t.Errorf("expected aud=metadata-audience, got: %v", payload["aud"])
	}
}

func TestSignLocalJWT_UUIDReplacement(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader: map[string]string{},
		TokenPayload: map[string]string{
			"jti": "${{UUID}}",
		},
	}

	jwt, err := SignLocalJWT(cfg, key, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	parts := strings.Split(jwt, ".")
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]interface{}
	json.Unmarshal(payloadBytes, &payload)

	jti, ok := payload["jti"].(string)
	if !ok {
		t.Fatal("expected jti claim to be a string")
	}
	if jti == "${{UUID}}" {
		t.Error("expected ${{UUID}} to be replaced with actual UUID")
	}
	// UUID format: 8-4-4-4-12 hex characters
	if len(jti) != 36 {
		t.Errorf("expected UUID length 36, got: %d", len(jti))
	}
}

func TestSignLocalJWT_AlgAndTypCannotBeOverridden(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader: map[string]string{
			"alg": "ES256",
			"typ": "at+jwt",
		},
		TokenPayload: map[string]string{},
	}

	jwt, err := SignLocalJWT(cfg, key, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	parts := strings.Split(jwt, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)

	// alg and typ should always be RS256/JWT regardless of config
	if header["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got: %s", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got: %s", header["typ"])
	}
}

func TestSignLocalJWT_SignatureValid(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader:  map[string]string{},
		TokenPayload: map[string]string{},
	}

	jwtToken, err := SignLocalJWT(cfg, key, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	parts := strings.Split(jwtToken, ".")
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	// Verify signature with public key
	dataToSign := parts[0] + "." + parts[1]
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed, sigBytes)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestReplaceDynamicVariables_UUID(t *testing.T) {
	result := replaceDynamicVariables("${{UUID}}")
	if result == "${{UUID}}" {
		t.Error("expected ${{UUID}} to be replaced")
	}
	if len(result) != 36 {
		t.Errorf("expected UUID length 36, got: %d", len(result))
	}
}

func TestReplaceDynamicVariables_NoReplacement(t *testing.T) {
	result := replaceDynamicVariables("plain-value")
	if result != "plain-value" {
		t.Errorf("expected 'plain-value', got: %s", result)
	}
}

func TestReplaceDynamicVariables_PartialUUID(t *testing.T) {
	result := replaceDynamicVariables("prefix-${{UUID}}-suffix")
	if strings.Contains(result, "${{UUID}}") {
		t.Error("expected ${{UUID}} to be replaced in partial string")
	}
	if !strings.HasPrefix(result, "prefix-") {
		t.Error("expected prefix to be preserved")
	}
	if !strings.HasSuffix(result, "-suffix") {
		t.Error("expected suffix to be preserved")
	}
}

func TestSignLocalJWT_EmptyMetadata(t *testing.T) {
	key := generateTestKey(t)
	cfg := config.Config{
		TokenHeader:  map[string]string{},
		TokenPayload: map[string]string{},
	}

	// Pass empty maps instead of nil
	jwt, err := SignLocalJWT(cfg, key, map[string]string{}, map[string]string{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if jwt == "" {
		t.Fatal("expected non-empty JWT")
	}
}
