package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"gopkg.in/yaml.v3"
)

var (
	debugLogEnabled bool

	configEnvironment           ConfigEnvironment
	configEnvironmentPrivateKey *rsa.PrivateKey

	configFile           ConfigFile
	configFilePrivateKey *rsa.PrivateKey

	// Caching

	tokenCache        = sync.Map{}
	tokenSoftLifetime float32
	createTokenMutex  = sync.Mutex{}

	// Utility variables

	pemKeyReplacer = strings.NewReplacer(
		"-----BEGIN PRIVATE KEY-----", "",
		"-----END PRIVATE KEY-----", "",
		"\\n", "",
		"\n", "",
	)

	// Global reusable HTTP client
	client *http.Client
)

const (
	// Environment variable names
	EnvConfigFilePath      = "CONFIG_FILE_PATH"
	EnvSoftTokenLifetime   = "SOFT_TOKEN_LIFETIME"
	EnvDebug               = "DEBUG"
	EnvPrivateKey          = "PRIVATE_KEY"
	EnvPrivateKeyId        = "PRIVATE_KEY_ID"
	EnvOauth2TokenURL      = "OAUTH2_TOKEN_URL"
	EnvOauth2ResponseField = "OAUTH2_RESPONSE_FIELD"
	EnvOauth2ClientId      = "OAUTH2_CLIENT_ID"
	EnvOauth2Audience      = "OAUTH2_AUDIENCE"

	// Common header and grant type
	POST                    = "POST"
	ContentType             = "Content-Type"
	FormURLEncoded          = "application/x-www-form-urlencoded"
	OauthJwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantType               = "grant_type"
	Assertion               = "assertion"

	// Metadata and JWT constants
	MetadataLocalTokenNamespace = "com.unitvectory.authzjwtbearerinjector.localtoken"
	RS256                       = "RS256"
	JWT                         = "JWT"

	// Error messages (performance-related if frequently thrown)
	ErrNoPrivateKey          = "no private key set"
	ErrNoOauth2TokenURL      = "no OAuth2 token URL set"
	ErrNoOauth2ResponseField = "no OAuth2 response field set"
)

func init() {
	// Get the tokenSoftLifetime from the environment variable
	// If set, parse SOFT_TOKEN_LIFETIME as a float32 if not set defualt to 0.5, if out of bounds set to 0.5
	tokenSoftLifetimeString := os.Getenv(EnvSoftTokenLifetime)
	tokenSoftLifetimeParsed, err := strconv.ParseFloat(tokenSoftLifetimeString, 32)
	if err != nil || tokenSoftLifetimeParsed < 0.0 || tokenSoftLifetimeParsed > 1.0 {
		tokenSoftLifetimeParsed = 0.5
	}
	tokenSoftLifetime = float32(tokenSoftLifetimeParsed)

	// Check if DEBUG logging is enabled via an environment variable
	debugLogEnabled = os.Getenv(EnvDebug) == "true"

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

type CachedToken struct {
	TokenValue CachedTokenValue
	Mutex      sync.Mutex
}

type CachedTokenValue struct {
	Token      string
	Expiry     time.Time
	SoftExpiry time.Time
	Issued     time.Time
}

// The YAML file configuration
type ConfigFile struct {
	PrivateKey   string            `yaml:"private_key"`
	PrivateKeyId string            `yaml:"private_key_id"`
	LocalToken   map[string]string `yaml:"local_token"`
	Oauth2       struct {
		TokenURL      string `yaml:"token_url"`
		ResponseField string `yaml:"response_field"`
		ClientId      string `yaml:"client_id"`
		Audience      string `yaml:"audience"`
	} `yaml:"oauth2"`
}

// The Environment variable configuration
type ConfigEnvironment struct {
	PrivateKey   string
	PrivateKeyId string
	LocalToken   map[string]string
	Oauth2       struct {
		TokenURL      string
		ResponseField string
		ClientId      string
		Audience      string
	}
}

type authServer struct {
	pb.UnimplementedAuthorizationServer
}

// Function for debug logging
func debugLog(message string, v ...any) {
	if debugLogEnabled {
		log.Printf(message, v...)
	}
}

func main() {
	// Determine the config file path
	configFilePath := os.Getenv(EnvConfigFilePath)
	if configFilePath == "" {
		configFilePath = "/app/config.yaml"
	}

	// Load in YAML file from config file and load into ConfigFile
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		log.Printf("config file does not exist: %v", err)
		log.Print("no config file found, using environment variables only")
		configFile = ConfigFile{}
	} else {
		configFileContent, err := os.ReadFile(configFilePath)
		if err != nil {
			log.Fatalf("failed to read config file: %v", err)
		}

		err = yaml.Unmarshal(configFileContent, &configFile)
		if err != nil {
			log.Fatalf("failed to unmarshal config file: %v", err)
		}

		// Log the config file local token (int a loop) and oauth variables
		if debugLogEnabled {
			for k, v := range configFile.LocalToken {
				debugLog("Config File Local Token: %s = %s", k, v)
			}
			debugLog("Config File OAuth2 Token URL: %s", configFile.Oauth2.TokenURL)
			debugLog("Config File OAuth2 Response Field: %s", configFile.Oauth2.ResponseField)
		}

		// Parse the private key from the config file
		if configFile.PrivateKey != "" {
			loadedConfigFilePrivateKey, err := parsePrivateKey(configFile.PrivateKey)
			if err != nil {
				log.Fatalf("Error parsing private key: %v", err)
			}
			log.Print("Successfully parsed private key from config file")
			configFilePrivateKey = loadedConfigFilePrivateKey
		} else {
			log.Print("No private key found in config file")
			configFilePrivateKey = nil
		}
	}

	// Load in the environment variables into ConfigEnvironment
	configEnvironment = ConfigEnvironment{
		PrivateKey:   os.Getenv(EnvPrivateKey),
		PrivateKeyId: os.Getenv(EnvPrivateKeyId),
		LocalToken:   map[string]string{},
		Oauth2: struct {
			TokenURL      string
			ResponseField string
			ClientId      string
			Audience      string
		}{
			TokenURL:      os.Getenv(EnvOauth2TokenURL),
			ResponseField: os.Getenv(EnvOauth2ResponseField),
			ClientId:      os.Getenv(EnvOauth2ClientId),
			Audience:      os.Getenv(EnvOauth2Audience),
		},
	}

	// Loop through all of the environment variables grabbing the LOCAL_TOKEN_ variables
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		key := pair[0]
		value := pair[1]

		// If the variable starts with LOCAL_TOKEN_, add it to the local token map removing the prefix
		if strings.HasPrefix(key, "LOCAL_TOKEN_") {
			configEnvironment.LocalToken[strings.TrimPrefix(key, "LOCAL_TOKEN_")] = value
		}
	}

	// Log the environment variables local token (int a loop) and oauth variables
	if debugLogEnabled {
		for k, v := range configEnvironment.LocalToken {
			debugLog("Environment Local Token: %s = %s", k, v)
		}
		debugLog("Environment OAuth2 Token URL: %s", configEnvironment.Oauth2.TokenURL)
		debugLog("Environment OAuth2 Response Field: %s", configEnvironment.Oauth2.ResponseField)
	}

	// Parse the private key from the environment variables
	if configEnvironment.PrivateKey != "" {
		loadedConfigEnvironmentPrivateKey, err := parsePrivateKey(configEnvironment.PrivateKey)
		if err != nil {
			log.Fatalf("Error parsing private key: %v", err)
		}
		log.Print("Successfully parsed private key from environment variables")
		configEnvironmentPrivateKey = loadedConfigEnvironmentPrivateKey
	} else {
		log.Print("No private key found in environment variables")
		configEnvironmentPrivateKey = nil
	}

	// Start the gRPC server
	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, &authServer{})

	// Enable gRPC reflection
	reflection.Register(grpcServer)

	log.Printf("authzjwtbearerinjector service listening on :50051...")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func parsePrivateKey(privateKeyString string) (*rsa.PrivateKey, error) {
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
		return nil, err
	}

	log.Println("Successfully parsed the RSA private key")
	return privateKey, nil
}

// Gets the preferred private key to use for local token generation
func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKey := configEnvironmentPrivateKey
	if privateKey == nil {
		privateKey = configFilePrivateKey
		if privateKey == nil {
			return nil, errors.New(ErrNoPrivateKey)
		}
	}
	return privateKey, nil
}

func generateJWT(metadataClaims map[string]string) (string, error) {

	debugLog("Generating JWT with metadata claims: %v", metadataClaims)

	// Get the private key
	privateKey, err := getPrivateKey()
	if err != nil {
		return "", err
	}

	header := map[string]string{
		"alg": RS256, // Only supporting RS256 for now
		"typ": JWT,
	}

	// Pull the KID from the config file first if it is populated
	if configFile.PrivateKeyId != "" {
		header["kid"] = configFile.PrivateKeyId
	}

	// Pull the KID from the environment variables if it is populated
	if configEnvironment.PrivateKeyId != "" {
		header["kid"] = configEnvironment.PrivateKeyId
	}

	headerBytes, _ := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Payload
	payload := map[string]interface{}{}

	// Use the config file claims first, lower priority
	for k, v := range configFile.LocalToken {
		payload[k] = v

		// Log the claims
		log.Printf("Added Config File Claim: %s = %s", k, v)
	}

	// The environment variables will overwrite the config file claims
	for k, v := range configEnvironment.LocalToken {
		payload[k] = v
		// Log the claims
		log.Printf("Added Environment Claim: %s = %s", k, v)
	}

	// The metadata claims will overwrite the environment variables
	for k, v := range metadataClaims {
		payload[k] = v
		// Log the claims
		log.Printf("Added Metadata Claim: %s = %s", k, v)
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
		debugLog("Error signing JWT: %v", err)
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Final JWT
	jwtToken := encodedHeader + "." + encodedPayload + "." + encodedSignature
	return jwtToken, nil
}

func exchangeJWTBearerForToken(jwtToken string) (string, time.Time, time.Time, error) {

	now := time.Now()

	debugLog("Exchanging JWT for token")

	// Get the preferred token URL to use for token exchange
	tokenURL := configEnvironment.Oauth2.TokenURL
	if tokenURL == "" {
		tokenURL = configFile.Oauth2.TokenURL
		if tokenURL == "" {
			return "", now, now, errors.New(ErrNoOauth2TokenURL)
		}
	}

	// Get the preferred response field to use for token exchange
	responseField := configEnvironment.Oauth2.ResponseField
	if responseField == "" {
		responseField = configFile.Oauth2.ResponseField
		if responseField == "" {
			return "", now, now, errors.New(ErrNoOauth2ResponseField)
		}
	}

	// Build the jwt-bearer token request
	data := url.Values{}
	data.Set(GrantType, OauthJwtBearerGrantType)
	data.Set(Assertion, jwtToken)

	// Add the clientId ifit is set in the config
	if configFile.Oauth2.ClientId != "" {
		data.Set("client_id", configFile.Oauth2.ClientId)
	}
	// Add the clientId if it is set in the environment variables
	if configEnvironment.Oauth2.ClientId != "" {
		data.Set("client_id", configEnvironment.Oauth2.ClientId)
	}

	// Add the audience if it is set in the config
	if configFile.Oauth2.Audience != "" {
		data.Set("audience", configFile.Oauth2.Audience)
	}

	// Add the audience if it is set in the environment variables
	if configEnvironment.Oauth2.Audience != "" {
		data.Set("audience", configEnvironment.Oauth2.Audience)
	}

	req, err := http.NewRequest(POST, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", now, now, err
	}
	req.Header.Set(ContentType, FormURLEncoded)
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

	token, ok := respData[responseField].(string)
	if !ok {
		return "", now, now, errors.New("OAuth2 token endpoint response does not contain field " + responseField)
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

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {

	metadataClaims := extractMetadataClaims(req)

	// Get the cached token
	start := time.Now()
	jwtToken, err := getCachedToken(metadataClaims)
	elapsed := time.Since(start)

	debugLog("getCachedToken took %s", elapsed)

	if err != nil {
		log.Printf("Error getting cached token: %v", err)

		// Return a CheckResponse with an error
		response := createErrorResponse()
		return response, nil
	}

	response := &pb.CheckResponse{
		Status: &status.Status{
			Code: int32(0),
		},
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "Authorization",
							Value: "Bearer " + jwtToken,
						},
					},
				},
			},
		},
	}

	return response, nil
}

func createErrorResponse() *pb.CheckResponse {
	response := &pb.CheckResponse{
		Status: &status.Status{
			Code:    int32(13),
			Message: "Internal server error",
		},
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(500),
				},
				Body: "Failed to request token",
			},
		},
	}
	return response
}

func extractMetadataClaims(req *pb.CheckRequest) map[string]string {
	claims := make(map[string]string)

	// Access and log route metadata filter values
	filterMetadata := req.Attributes.GetRouteMetadataContext().GetFilterMetadata()

	// Check for the specific metadata key and log the value
	if metadata, ok := filterMetadata[MetadataLocalTokenNamespace]; ok {
		if fields := metadata.GetFields(); fields != nil {
			// Loop through all of the fields and add to claims map
			for key, value := range fields {
				claims[key] = value.GetStringValue()
			}
		}
	} else {
		debugLog("%s not found in filter metadata", MetadataLocalTokenNamespace)
	}

	return claims
}

func getCachedToken(claims map[string]string) (string, error) {
	// Step 1: Hash the claims to create a unique cache key
	cacheKey := hashClaims(claims)

	debugLog("getCachedToken: %s", cacheKey)

	// Step 2: Try to load the cached token entry
	cachedEntry, exists := tokenCache.Load(cacheKey)

	var cachedToken *CachedToken

	if !exists {
		// Step 3: Lock to ensure that only one goroutine can create a new token for the same cache key
		createTokenMutex.Lock()
		defer createTokenMutex.Unlock()

		// Check again if the token was created while waiting for the lock
		cachedEntry, exists = tokenCache.Load(cacheKey)

		if !exists {
			// Step 4: If no cached entry exists, create a new one with a locked mutex to block other requests
			newCachedToken := &CachedToken{
				Mutex: sync.Mutex{},
			}
			tokenCache.Store(cacheKey, newCachedToken)
			cachedToken = newCachedToken

			debugLog("Cache miss with token for: %s", cacheKey)
		}
	}

	if exists {
		// Step 5: Type assert the cached entry as *CachedToken
		cachedToken = cachedEntry.(*CachedToken)

		if debugLogEnabled {
			// Token found, log how long until the token expires
			timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
			debugLog("Token found in cache, expires in: %s", timeTillExpiry)
			// And the soft expiration time
			timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
			debugLog("Token found in cache, soft expires in: %s", timeTillSoftExpiry)
		}

		// Step 6: Check if the token is still within soft expiry
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			debugLog("Returning cached token for: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}
	}

	debugLog("Waiting for lock on: %s", cacheKey)

	// Step 7: Lock the token generation if it hasn't been done yet
	cachedToken.Mutex.Lock()
	defer cachedToken.Mutex.Unlock()

	debugLog("Lock acquired on: %s", cacheKey)

	// Step 8: After locking, check again if the token is still valid
	if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
		debugLog("Returning cached generated after getting lock token for: %s", cacheKey)
		return cachedToken.TokenValue.Token, nil
	}

	// Step 9: Generate a new JWT
	localJWT, err := generateJWT(claims)
	if err != nil {
		// If generation fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			debugLog("Soft expired token generate failed, using existing token: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}

		debugLog("Expired token generated failed: %s", cacheKey)
		return "", err
	}

	// Step 10: Exchange the local JWT for an actual token
	token, expiry, issuedAt, err := exchangeJWTBearerForToken(localJWT)
	if err != nil {
		// If token exchange fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			debugLog("Soft expired token exchange failed, using existing token: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}

		debugLog("Expired token exchange failed: %s", cacheKey)
		// If the cached token is also expired, return an error
		return "", err
	}

	// Step 11: Calculate soft expiry based on the configurable lifetime ratio
	lifetime := expiry.Sub(issuedAt)
	softExpiry := time.Now().Add(time.Duration(float32(lifetime) * tokenSoftLifetime))

	// Step 12: Update the cached token value
	newCachedTokenValue := CachedTokenValue{
		Token:      token,
		Expiry:     expiry,
		SoftExpiry: softExpiry,
		Issued:     issuedAt,
	}

	cachedToken.TokenValue = newCachedTokenValue

	if debugLogEnabled {
		// Log how long until the token expires
		timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
		debugLog("New token generated, expires in: %s", timeTillExpiry)
		// And the soft expiration time
		timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
		debugLog("New token generated, soft expires in: %s", timeTillSoftExpiry)

		debugLog("New token request successful: %s", cacheKey)
	}

	return token, nil
}

func hashClaims(claims map[string]string) string {
	h := sha256.New()
	// Extract the keys from the map and sort them
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write the sorted key-value pairs to the hash
	for _, k := range keys {
		h.Write([]byte(fmt.Sprintf("%s:%v", k, claims[k])))
	}

	// Return the final hash as a hexadecimal string
	return hex.EncodeToString(h.Sum(nil))
}
