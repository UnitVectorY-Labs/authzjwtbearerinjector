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
	debugLogger     *log.Logger
	debugLogEnabled bool

	configEnvironment           ConfigEnvironment
	configEnvironmentPrivateKey *rsa.PrivateKey

	configFile           ConfigFile
	configFilePrivateKey *rsa.PrivateKey

	// Caching

	tokenCache        = sync.Map{}
	tokenSoftLifetime float32

	// Utility variables

	pemKeyReplacer = strings.NewReplacer(
		"-----BEGIN PRIVATE KEY-----", "",
		"-----END PRIVATE KEY-----", "",
		"\\n", "",
		"\n", "",
	)
)

const (
	metadataLocalTokenNamespace = "com.unitvectory.authzjwtbearerinjector.localtoken"
)

func init() {
	// Get the tokenSoftLifetime from the environment variable
	// If set, parse SOFT_TOKEN_LIFETIME as a float32 if not set defualt to 0.5, if out of bounds set to 0.5
	tokenSoftLifetimeString := os.Getenv("SOFT_TOKEN_LIFETIME")
	tokenSoftLifetimeParsed, err := strconv.ParseFloat(tokenSoftLifetimeString, 32)
	if err != nil || tokenSoftLifetimeParsed < 0.0 || tokenSoftLifetimeParsed > 1.0 {
		tokenSoftLifetimeParsed = 0.5
	}
	tokenSoftLifetime = float32(tokenSoftLifetimeParsed)

	// Check if debug logging is enabled via an environment variable
	if os.Getenv("DEBUG") == "true" {
		debugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
		debugLogEnabled = true
	} else {
		// Create a no-op logger to discard debug messages
		debugLogger = log.New(os.Stderr, "", 0)
		debugLogger.SetOutput(os.Stderr)
		debugLogEnabled = false
	}
}

type CachedToken struct {
	Token      string
	Expiry     time.Time
	SoftExpiry time.Time
	Issued     time.Time
	Mutex      sync.Mutex
}

// The YAML file configuration
type ConfigFile struct {
	PrivateKey string            `yaml:"private_key"`
	LocalToken map[string]string `yaml:"local_token"`
	Oauth2     struct {
		TokenURL      string `yaml:"token_url"`
		ResponseField string `yaml:"response_field"`
	} `yaml:"oauth2"`
}

// The Environment variable configuration
type ConfigEnvironment struct {
	PrivateKey string
	LocalToken map[string]string
	Oauth2     struct {
		TokenURL      string
		ResponseField string
	}
}

type authServer struct {
	pb.UnimplementedAuthorizationServer
}

func main() {
	// Determine the config file path
	configFilePath := os.Getenv("CONFIG_FILE_PATH")
	if configFilePath == "" {
		configFilePath = "/app/config.yaml"
	}

	// Load in YAML file from fonfig file and load into ConfigFile
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

		if debugLogEnabled {
			// Log the config file local token (int a loop) and oauth variables
			for k, v := range configFile.LocalToken {
				log.Printf("Config File Local Token: %s = %s", k, v)
			}
			log.Printf("Config File OAuth2 Token URL: %s", configFile.Oauth2.TokenURL)
			log.Printf("Config File OAuth2 Response Field: %s", configFile.Oauth2.ResponseField)
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
		PrivateKey: os.Getenv("PRIVATE_KEY"),
		LocalToken: map[string]string{},
		Oauth2: struct {
			TokenURL      string
			ResponseField string
		}{
			TokenURL:      os.Getenv("OAUTH2_TOKEN_URL"),
			ResponseField: os.Getenv("OAUTH2_RESPONSE_FIELD"),
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

	if debugLogEnabled {
		// Log the environment variables local token (int a loop) and oauth variables
		for k, v := range configEnvironment.LocalToken {
			log.Printf("Environment Local Token: %s = %s", k, v)
		}
		log.Printf("Environment OAuth2 Token URL: %s", configEnvironment.Oauth2.TokenURL)
		log.Printf("Environment OAuth2 Response Field: %s", configEnvironment.Oauth2.ResponseField)
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
			return nil, errors.New("no private key set")
		}
	}
	return privateKey, nil
}

func generateJWT(metadataClaims map[string]string) (string, error) {

	if debugLogEnabled {
		log.Printf("Generating JWT with metadata claims: %v", metadataClaims)
	}

	// Get the private key
	privateKey, err := getPrivateKey()
	if err != nil {
		return "", err
	}

	header := map[string]string{
		"alg": "RS256", // Only supporting RS256 for now
		"typ": "JWT",
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

	// THe iat and exp claims are always added to the payload
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(time.Hour).Unix() // Defaulting to industry standard of 1 hour

	if debugLogEnabled {
		// Log the payload claim
		for k, v := range payload {
			log.Printf("Payload Claim: %s = %s", k, v)
		}
	}

	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Signature
	dataToSign := encodedHeader + "." + encodedPayload
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Final JWT
	jwtToken := encodedHeader + "." + encodedPayload + "." + encodedSignature
	return jwtToken, nil
}

func exchangeJWTBearerForToken(jwtToken string) (string, time.Time, time.Time, error) {

	now := time.Now()

	if debugLogEnabled {
		log.Print("Exchanging JWT for token")
	}

	// Get the preferred token URL to use for token exchange
	tokenURL := configEnvironment.Oauth2.TokenURL
	if tokenURL == "" {
		tokenURL = configFile.Oauth2.TokenURL
		if tokenURL == "" {
			return "", now, now, errors.New("no OAuth2 token URL set")
		}
	}

	// Get the preferred response field to use for token exchange
	responseField := configEnvironment.Oauth2.ResponseField
	if responseField == "" {
		responseField = configFile.Oauth2.ResponseField
		if responseField == "" {
			return "", now, now, errors.New("no OAuth2 response field set")
		}
	}

	// Build the jwt-bearer token request
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", jwtToken)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", now, now, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
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

	if debugLogEnabled {
		log.Printf("getCachedToken took %s", elapsed)
	}

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
	if metadata, ok := filterMetadata[metadataLocalTokenNamespace]; ok {
		if fields := metadata.GetFields(); fields != nil {
			// Loop through all of the fields and add to claims map
			for key, value := range fields {
				claims[key] = value.GetStringValue()
			}
		}
	} else if debugLogEnabled {
		log.Printf("%s not found in filter metadata", metadataLocalTokenNamespace)
	}

	return claims
}

func getCachedToken(claims map[string]string) (string, error) {
	// Step 1: Hash the claims to create a unique cache key
	cacheKey := hashClaims(claims)

	if debugLogEnabled {
		log.Printf("getCachedToken: %s", cacheKey)
	}

	// Step 2: Try to load the cached token entry
	cachedEntry, exists := tokenCache.Load(cacheKey)

	var cachedToken *CachedToken
	if exists {
		// Type assert the cached entry as *CachedToken
		cachedToken = cachedEntry.(*CachedToken)

		// Lock the cached token to ensure thread-safe access
		cachedToken.Mutex.Lock()
		defer cachedToken.Mutex.Unlock()

		// Step 3: Check if the token is still within soft expiry
		if time.Now().Before(cachedToken.SoftExpiry) {
			if debugLogEnabled {
				log.Printf("Returning cached token for: %s", cacheKey)
			}

			return cachedToken.Token, nil
		}
	} else {
		// If no cached entry exists, create a new one with a locked mutex to block other requests
		newCachedToken := &CachedToken{
			Mutex: sync.Mutex{},
		}
		tokenCache.Store(cacheKey, newCachedToken)
		cachedToken = newCachedToken

		if debugLogEnabled {
			log.Printf("Cache miss with token for: %s", cacheKey)
		}
	}

	// Step 4: Lock the token generation if it hasn't been done yet
	cachedToken.Mutex.Lock()
	defer cachedToken.Mutex.Unlock()

	// Step 5: After locking, check again if the token is still valid
	if time.Now().Before(cachedToken.SoftExpiry) {
		return cachedToken.Token, nil
	}

	// Step 6: If we reach here, we need to generate a new JWT
	localJWT, err := generateJWT(claims)
	if err != nil {
		// Return the cached token if it's still valid
		if time.Now().Before(cachedToken.SoftExpiry) {
			if debugLogEnabled {
				log.Printf("Soft expired token generate failed, using existing token : %s", cacheKey)
			}

			return cachedToken.Token, nil
		}

		if debugLogEnabled {
			log.Printf("Expired token generated failed: %s", cacheKey)
		}

		return "", err
	}

	// Step 7: Exchange the local JWT for an actual token
	token, expiry, issuedAt, err := exchangeJWTBearerForToken(localJWT)
	if err != nil {
		// If token exchange fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.SoftExpiry) {

			if debugLogEnabled {
				log.Printf("Soft expired token exchange failed, using existing token : %s", cacheKey)
			}

			return cachedToken.Token, nil
		}

		if debugLogEnabled {
			log.Printf("Expired token exchange failed: %s", cacheKey)
		}

		// If the cached token is also expired, return an error
		return "", err
	}

	// Calculate soft expiry based on the configurable lifetime ratio
	lifetime := expiry.Sub(issuedAt)
	softExpiry := time.Now().Add(time.Duration(float32(lifetime) * tokenSoftLifetime))

	// Update the cached entry with the new token and expiry times
	cachedToken.Token = token
	cachedToken.Expiry = expiry
	cachedToken.SoftExpiry = softExpiry
	cachedToken.Issued = issuedAt

	if debugLogEnabled {
		log.Printf("New token request successful: %s", cacheKey)
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
