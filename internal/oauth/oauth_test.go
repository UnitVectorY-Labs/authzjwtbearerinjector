package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	config "github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/config"
)

// createTestJWT creates a minimal JWT token with given claims for testing
func createTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "none", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".signature"
}

func TestExchangeJWTBearerForToken_Success(t *testing.T) {
	now := time.Now()
	claims := map[string]interface{}{
		"exp": float64(now.Add(1 * time.Hour).Unix()),
		"iat": float64(now.Unix()),
	}
	responseToken := createTestJWT(t, claims)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("expected POST method, got: %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected application/x-www-form-urlencoded, got: %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("User-Agent") != "authzjwtbearerinjector" {
			t.Errorf("expected User-Agent authzjwtbearerinjector, got: %s", r.Header.Get("User-Agent"))
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("assertion") == "" {
			t.Error("expected assertion in request")
		}

		resp := map[string]interface{}{
			"access_token": responseToken,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.Config{
		OauthTokenUrl:      server.URL,
		OauthResponseField: "access_token",
		OauthRequest: map[string]string{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":  "${{JWT}}",
		},
	}

	token, expiry, issuedAt, err := ExchangeJWTBearerForToken(cfg, "test-jwt", nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != responseToken {
		t.Errorf("expected token %s, got: %s", responseToken, token)
	}
	if expiry.IsZero() {
		t.Error("expected non-zero expiry")
	}
	if issuedAt.IsZero() {
		t.Error("expected non-zero issuedAt")
	}
}

func TestExchangeJWTBearerForToken_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_grant"))
	}))
	defer server.Close()

	cfg := config.Config{
		OauthTokenUrl:      server.URL,
		OauthResponseField: "access_token",
		OauthRequest:       map[string]string{},
	}

	_, _, _, err := ExchangeJWTBearerForToken(cfg, "test-jwt", nil)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("expected error to contain status code, got: %v", err)
	}
}

func TestExchangeJWTBearerForToken_MissingField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"other_field": "value",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.Config{
		OauthTokenUrl:      server.URL,
		OauthResponseField: "access_token",
		OauthRequest:       map[string]string{},
	}

	_, _, _, err := ExchangeJWTBearerForToken(cfg, "test-jwt", nil)
	if err == nil {
		t.Fatal("expected error when response field is missing")
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("expected error to mention missing field, got: %v", err)
	}
}

func TestExchangeJWTBearerForToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json"))
	}))
	defer server.Close()

	cfg := config.Config{
		OauthTokenUrl:      server.URL,
		OauthResponseField: "access_token",
		OauthRequest:       map[string]string{},
	}

	_, _, _, err := ExchangeJWTBearerForToken(cfg, "test-jwt", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestExchangeJWTBearerForToken_MetadataOauthRequest(t *testing.T) {
	var receivedScope string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedScope = r.Form.Get("scope")

		now := time.Now()
		claims := map[string]interface{}{
			"exp": float64(now.Add(1 * time.Hour).Unix()),
			"iat": float64(now.Unix()),
		}
		responseToken := createTestJWT(t, claims)
		resp := map[string]interface{}{"access_token": responseToken}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := config.Config{
		OauthTokenUrl:      server.URL,
		OauthResponseField: "access_token",
		OauthRequest: map[string]string{
			"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
			"assertion":  "${{JWT}}",
		},
	}

	metadataOauth := map[string]string{
		"scope": "openid",
	}

	_, _, _, err := ExchangeJWTBearerForToken(cfg, "test-jwt", metadataOauth)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if receivedScope != "openid" {
		t.Errorf("expected scope=openid, got: %s", receivedScope)
	}
}

func TestExchangeJWTBearerForToken_InvalidURL(t *testing.T) {
	cfg := config.Config{
		OauthTokenUrl:      "http://invalid.localhost:99999/token",
		OauthResponseField: "access_token",
		OauthRequest:       map[string]string{},
	}

	_, _, _, err := ExchangeJWTBearerForToken(cfg, "test-jwt", nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestExtractExpirationClaims_ValidJWT(t *testing.T) {
	now := time.Now()
	expTime := now.Add(1 * time.Hour)
	claims := map[string]interface{}{
		"exp": float64(expTime.Unix()),
		"iat": float64(now.Unix()),
	}
	token := createTestJWT(t, claims)

	exp, iat := extractExpirationClaims(token)

	if exp.Unix() != expTime.Unix() {
		t.Errorf("expected exp %v, got: %v", expTime.Unix(), exp.Unix())
	}
	if iat.Unix() != now.Unix() {
		t.Errorf("expected iat %v, got: %v", now.Unix(), iat.Unix())
	}
}

func TestExtractExpirationClaims_InvalidFormat(t *testing.T) {
	// Not a JWT - should return defaults
	exp, iat := extractExpirationClaims("not-a-jwt")

	// Should return defaults (now + 1 hour, now)
	now := time.Now()
	if exp.Before(now) {
		t.Error("expected exp to be in the future")
	}
	if iat.After(now.Add(1 * time.Second)) {
		t.Error("expected iat to be around now")
	}
}

func TestExtractExpirationClaims_InvalidBase64(t *testing.T) {
	exp, iat := extractExpirationClaims("header.!!!invalid!!!.signature")

	now := time.Now()
	if exp.Before(now) {
		t.Error("expected default exp in the future")
	}
	if iat.After(now.Add(1 * time.Second)) {
		t.Error("expected default iat around now")
	}
}

func TestExtractExpirationClaims_InvalidJSON(t *testing.T) {
	invalidPayload := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	token := "header." + invalidPayload + ".signature"

	exp, iat := extractExpirationClaims(token)

	now := time.Now()
	if exp.Before(now) {
		t.Error("expected default exp in the future")
	}
	if iat.After(now.Add(1 * time.Second)) {
		t.Error("expected default iat around now")
	}
}

func TestExtractExpirationClaims_MissingClaims(t *testing.T) {
	// JWT with no exp or iat
	claims := map[string]interface{}{
		"sub": "test",
	}
	token := createTestJWT(t, claims)

	exp, iat := extractExpirationClaims(token)

	now := time.Now()
	if exp.Before(now) {
		t.Error("expected default exp in the future")
	}
	if iat.After(now.Add(1 * time.Second)) {
		t.Error("expected default iat around now")
	}
}

func TestReplaceJwtVariables_JWT(t *testing.T) {
	result := replaceJwtVariables("${{JWT}}", "my-jwt-token")
	if result != "my-jwt-token" {
		t.Errorf("expected 'my-jwt-token', got: %s", result)
	}
}

func TestReplaceJwtVariables_UUID(t *testing.T) {
	result := replaceJwtVariables("${{UUID}}", "jwt")
	if result == "${{UUID}}" {
		t.Error("expected ${{UUID}} to be replaced")
	}
	if len(result) != 36 {
		t.Errorf("expected UUID length 36, got: %d", len(result))
	}
}

func TestReplaceJwtVariables_Both(t *testing.T) {
	result := replaceJwtVariables("jwt:${{JWT}}", "my-jwt")
	if result != "jwt:my-jwt" {
		t.Errorf("expected 'jwt:my-jwt', got: %s", result)
	}
}

func TestReplaceJwtVariables_NoReplacement(t *testing.T) {
	result := replaceJwtVariables("plain-value", "jwt")
	if result != "plain-value" {
		t.Errorf("expected 'plain-value', got: %s", result)
	}
}
