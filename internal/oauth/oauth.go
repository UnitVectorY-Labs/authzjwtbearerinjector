package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	config "authzjwtbearerinjector/internal/config"
	logger "authzjwtbearerinjector/internal/logger"
)

var (
	// Global reusable HTTP client
	client *http.Client
)

const (
	post           = "POST"
	contentType    = "Content-Type"
	formURLEncoded = "application/x-www-form-urlencoded"
)

func init() {
	// Create a reusable HTTP client with a custom Transport to set the User-Agent header
	genericTimeout := 5 * time.Second
	client = &http.Client{
		Timeout: genericTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   genericTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: genericTimeout,
		},
	}
}

func ExchangeJWTBearerForToken(config config.Config, jwt string, metadataOauthRequest map[string]string) (string, time.Time, time.Time, error) {

	now := time.Now()

	logger.DebugLog("Exchanging JWT for token")

	// Build the jwt-bearer token request
	data := url.Values{}

	for k, v := range config.OauthRequest {
		data.Set(k, replaceJwtVariables(v, jwt))
		logger.DebugLog("Request Attribute: %s = %s", k, v)
	}

	for k, v := range metadataOauthRequest {
		data.Set(k, replaceJwtVariables(v, jwt))
		logger.DebugLog("Request Attribute (Metadata): %s = %s", k, v)
	}

	req, err := http.NewRequest(post, config.OauthTokenUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return "", now, now, err
	}
	req.Header.Set(contentType, formURLEncoded)
	req.Header.Set("User-Agent", "authzjwtbearerinjector")

	resp, err := client.Do(req)
	if err != nil {
		return "", now, now, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", now, now, errors.New("OAuth2 token endpoint returned status " + resp.Status + ": " + string(bodyBytes))
	}

	var respData map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&respData)
	if err != nil {
		return "", now, now, err
	}

	token, ok := respData[config.OauthResponseField].(string)
	if !ok {
		return "", now, now, errors.New("OAuth2 token endpoint response does not contain field " + config.OauthResponseField)
	}

	// Extract the expiration time
	expirationTime, issuedAtTime := extractExpirationClaims(token)

	return token, expirationTime, issuedAtTime, nil
}

func extractExpirationClaims(token string) (time.Time, time.Time) {
	// Define default values for exp (now + 1 hour) and iat (now)
	now := time.Now()
	defaultExp := now.Add(1 * time.Hour)
	defaultIat := now

	// Split the token into parts (header, payload, signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		// If it's not a valid JWT format, return default values
		return defaultExp, defaultIat
	}

	// Base64 decode the payload (second part of the JWT)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// If decoding fails, return default values
		return defaultExp, defaultIat
	}

	// Parse the payload into a map
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		// If parsing the payload fails, return default values
		return defaultExp, defaultIat
	}

	// Extract the exp claim
	expFloat, ok := claims["exp"].(float64)
	expirationTime := defaultExp
	if ok {
		expirationTime = time.Unix(int64(expFloat), 0)
	}

	// Extract the iat claim
	iatFloat, ok := claims["iat"].(float64)
	issuedAtTime := defaultIat
	if ok {
		issuedAtTime = time.Unix(int64(iatFloat), 0)
	}

	// Return the extracted or default values
	return expirationTime, issuedAtTime
}

func replaceJwtVariables(input string, jwt string) string {
	if strings.Contains(input, "${{JWT}}") {
		input = strings.ReplaceAll(input, "${{JWT}}", jwt)
	}
	if strings.Contains(input, "${{UUID}}") {
		input = strings.ReplaceAll(input, "${{UUID}}", uuid.New().String())
	}
	return input
}
