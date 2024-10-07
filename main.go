package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"sort"
	"strings"
	"sync"
	"time"

	authz "authzjwtbearerinjector/internal"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

var (
	config     authz.Config
	privateKey *rsa.PrivateKey

	// Caching

	tokenCache       = sync.Map{}
	createTokenMutex = sync.Mutex{}

	// Global reusable HTTP client
	client *http.Client
)

const (

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

type authServer struct {
	pb.UnimplementedAuthorizationServer
}

func main() {

	// Load in the config
	config = *authz.NewConfig()

	// Parse the private key
	parsedPrivateKey, err := authz.ParsePrivateKey(config.PrivateKey)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}
	privateKey = parsedPrivateKey

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

func generateJWT(metadataClaims map[string]string) (string, error) {

	authz.DebugLog("Generating JWT with metadata claims: %v", metadataClaims)

	header := map[string]string{
		"alg": RS256, // Only supporting RS256 for now
		"typ": JWT,
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
		authz.DebugLog("Added Config File Claim: %s = %s", k, v)
	}

	// The metadata claims will overwrite the environment variables
	for k, v := range metadataClaims {
		payload[k] = v
		// Log the claims
		authz.DebugLog("Added Metadata Claim: %s = %s", k, v)
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
		authz.DebugLog("Error signing JWT: %v", err)
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Final JWT
	jwtToken := encodedHeader + "." + encodedPayload + "." + encodedSignature
	return jwtToken, nil
}

func exchangeJWTBearerForToken(jwtToken string) (string, time.Time, time.Time, error) {

	now := time.Now()

	authz.DebugLog("Exchanging JWT for token")

	// Build the jwt-bearer token request
	data := url.Values{}
	data.Set(GrantType, OauthJwtBearerGrantType)
	data.Set(Assertion, jwtToken)

	// Add the clientId if it is set in the config
	if config.Oauth2.ClientId != "" {
		data.Set("client_id", config.Oauth2.ClientId)
	}

	// Add the audience if it is set in the config
	if config.Oauth2.Audience != "" {
		data.Set("audience", config.Oauth2.Audience)
	}

	req, err := http.NewRequest(POST, config.Oauth2.TokenURL, strings.NewReader(data.Encode()))
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

	token, ok := respData[config.Oauth2.ResponseField].(string)
	if !ok {
		return "", now, now, errors.New("OAuth2 token endpoint response does not contain field " + config.Oauth2.ResponseField)
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

	authz.DebugLog("getCachedToken took %s", elapsed)

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
		authz.DebugLog("%s not found in filter metadata", MetadataLocalTokenNamespace)
	}

	return claims
}

func getCachedToken(claims map[string]string) (string, error) {
	// Step 1: Hash the claims to create a unique cache key
	cacheKey := hashClaims(claims)

	authz.DebugLog("getCachedToken: %s", cacheKey)

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

			authz.DebugLog("Cache miss with token for: %s", cacheKey)
		}
	}

	if exists {
		// Step 5: Type assert the cached entry as *CachedToken
		cachedToken = cachedEntry.(*CachedToken)

		if authz.IsDebugLogEnabled() {
			// Token found, log how long until the token expires
			timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
			authz.DebugLog("Token found in cache, expires in: %s", timeTillExpiry)
			// And the soft expiration time
			timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
			authz.DebugLog("Token found in cache, soft expires in: %s", timeTillSoftExpiry)
		}

		// Step 6: Check if the token is still within soft expiry
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			authz.DebugLog("Returning cached token for: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}
	}

	authz.DebugLog("Waiting for lock on: %s", cacheKey)

	// Step 7: Lock the token generation if it hasn't been done yet
	cachedToken.Mutex.Lock()
	defer cachedToken.Mutex.Unlock()

	authz.DebugLog("Lock acquired on: %s", cacheKey)

	// Step 8: After locking, check again if the token is still valid
	if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
		authz.DebugLog("Returning cached generated after getting lock token for: %s", cacheKey)
		return cachedToken.TokenValue.Token, nil
	}

	// Step 9: Generate a new JWT
	localJWT, err := generateJWT(claims)
	if err != nil {
		// If generation fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			authz.DebugLog("Soft expired token generate failed, using existing token: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}

		authz.DebugLog("Expired token generated failed: %s", cacheKey)
		return "", err
	}

	// Step 10: Exchange the local JWT for an actual token
	token, expiry, issuedAt, err := exchangeJWTBearerForToken(localJWT)
	if err != nil {
		// If token exchange fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			authz.DebugLog("Soft expired token exchange failed, using existing token: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}

		authz.DebugLog("Expired token exchange failed: %s", cacheKey)
		// If the cached token is also expired, return an error
		return "", err
	}

	// Step 11: Calculate soft expiry based on the configurable lifetime ratio
	lifetime := expiry.Sub(issuedAt)
	softExpiry := time.Now().Add(time.Duration(float32(lifetime) * float32(config.SoftTokenLifetime)))

	// Step 12: Update the cached token value
	newCachedTokenValue := CachedTokenValue{
		Token:      token,
		Expiry:     expiry,
		SoftExpiry: softExpiry,
		Issued:     issuedAt,
	}

	cachedToken.TokenValue = newCachedTokenValue

	if authz.IsDebugLogEnabled() {
		// Log how long until the token expires
		timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
		authz.DebugLog("New token generated, expires in: %s", timeTillExpiry)
		// And the soft expiration time
		timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
		authz.DebugLog("New token generated, soft expires in: %s", timeTillSoftExpiry)

		authz.DebugLog("New token request successful: %s", cacheKey)
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
