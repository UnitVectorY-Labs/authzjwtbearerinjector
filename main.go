package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	payload["exp"] = time.Now().Add(time.Hour).Unix()

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

func exchangeJWTBearerForToken(jwtToken string) (string, error) {

	if debugLogEnabled {
		log.Print("Exchanging JWT for token")
	}

	// Get the preferred token URL to use for token exchange
	tokenURL := configEnvironment.Oauth2.TokenURL
	if tokenURL == "" {
		tokenURL = configFile.Oauth2.TokenURL
		if tokenURL == "" {
			return "", errors.New("no OAuth2 token URL set")
		}
	}

	// Get the preferred response field to use for token exchange
	responseField := configEnvironment.Oauth2.ResponseField
	if responseField == "" {
		responseField = configFile.Oauth2.ResponseField
		if responseField == "" {
			return "", errors.New("no OAuth2 response field set")
		}
	}

	// Build the jwt-bearer token request
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", jwtToken)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", errors.New("OAuth2 token endpoint returned status " + resp.Status + ": " + string(bodyBytes))
	}

	var respData map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&respData)
	if err != nil {
		return "", err
	}

	token, ok := respData[responseField].(string)
	if !ok {
		return "", errors.New("OAuth2 token endpoint response does not contain field " + responseField)
	}

	return token, nil
}

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {

	metadataClaims := extractMetadataClaims(req)

	// Generate and log the JWT, this is just for debugging purposes as this
	// implementation is not complete and is a work in progress
	localJwtToken, err := generateJWT(metadataClaims)
	if err != nil {
		log.Printf("Error generating JWT: %v", err)

		// Return a CheckResponse with an error
		response := createErrorResponse()
		return response, nil
	}

	// Exchange the JWT for a token
	jwtToken, err := exchangeJWTBearerForToken(localJwtToken)
	if err != nil {
		log.Printf("Error exchanging JWT for token: %v", err)

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
	} else {
		// log.Printf("%s not found in filter metadata", metadataLocalTokenNamespace)
	}

	return claims
}
