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
	"log"
	"net"
	"os"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Config holds the environment variables
type Config struct {
	PrivateKey     string
	PrivateKeyVal  *rsa.PrivateKey
	LocalTokenIss  string
	LocalTokenSub  string
	LocalTokenAud  string
	Oauth2TokenURL string
}

// Global config instance
var config Config

type authServer struct {
	pb.UnimplementedAuthorizationServer
}

func parsePrivateKey() (*rsa.PrivateKey, error) {
	// Log the raw environment variable for the private key
	log.Println("Raw PRIVATE_KEY environment variable:")
	log.Println(config.PrivateKey)

	// Remove the PEM header, footer, and any newlines
	privateKeyCleaned := strings.ReplaceAll(config.PrivateKey, "-----BEGIN PRIVATE KEY-----", "")
	privateKeyCleaned = strings.ReplaceAll(privateKeyCleaned, "-----END PRIVATE KEY-----", "")
	privateKeyCleaned = strings.ReplaceAll(privateKeyCleaned, "\\n", "")
	privateKeyCleaned = strings.TrimSpace(privateKeyCleaned) // Just in case there are extra spaces

	// Log the private key for debugging
	log.Println("Cleaned PRIVATE_KEY:")
	log.Println(privateKeyCleaned)

	// Decode the Base64-encoded private key
	decodedKey, err := base64.StdEncoding.DecodeString(privateKeyCleaned)
	if err != nil {
		log.Fatalf("failed to base64 decode private key: %v", err)
	}
	log.Println("Successfully Base64 decoded the private key")

	// Parse the PKCS#8 private key
	parsedKey, err := x509.ParsePKCS8PrivateKey(decodedKey)
	if err != nil {
		log.Fatalf("failed to parse PKCS#8 private key: %v", err)
	}

	// Ensure the key is of type *rsa.PrivateKey
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("not an RSA private key")
	}

	log.Println("Successfully parsed the RSA private key")
	return privateKey, nil
}

func generateJWT() (string, error) {
	// Header
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Payload
	payload := map[string]interface{}{
		"iss":             config.LocalTokenIss,
		"sub":             config.LocalTokenSub,
		"aud":             config.LocalTokenAud,
		"iat":             time.Now().Unix(),
		"exp":             time.Now().Add(time.Hour).Unix(),
		"target_audience": "http://example.com",
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Signature
	dataToSign := encodedHeader + "." + encodedPayload
	hash := sha256.New()
	hash.Write([]byte(dataToSign))
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, config.PrivateKeyVal, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Final JWT
	jwtToken := encodedHeader + "." + encodedPayload + "." + encodedSignature
	return jwtToken, nil
}

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {

	// Loop through the context extensiosn 	req.Attributes.ContextExtensions logging them
	var extensions []string
	for k, v := range req.Attributes.ContextExtensions {
		log.Printf("Context Extension: %s = %s", k, v)
		extensions = append(extensions, k+"="+v)
	}
	concatenatedExtensions := strings.Join(extensions, ";")
	log.Printf("Concatenated Extensions: %s", concatenatedExtensions)

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
							Value: "Bearer " + concatenatedExtensions,
						},
					},
				},
			},
		},
	}

	return response, nil
}

func getEnvOrFatal(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s environment variable is required", key)
	}
	return value
}

func main() {
	// Initialize the config with environment variables
	config = Config{
		PrivateKey:     getEnvOrFatal("PRIVATE_KEY"),
		LocalTokenIss:  getEnvOrFatal("LOCAL_TOKEN_ISS"),
		LocalTokenSub:  getEnvOrFatal("LOCAL_TOKEN_SUB"),
		LocalTokenAud:  getEnvOrFatal("LOCAL_TOKEN_AUD"),
		Oauth2TokenURL: getEnvOrFatal("OAUTH2_TOKEN_URL"),
	}

	// Log the environment variables
	log.Println("Config:")
	log.Printf("PRIVATE_KEY: %s", config.PrivateKey)
	log.Printf("LOCAL_TOKEN_ISS: %s", config.LocalTokenIss)
	log.Printf("LOCAL_TOKEN_SUB: %s", config.LocalTokenSub)
	log.Printf("LOCAL_TOKEN_AUD: %s", config.LocalTokenAud)
	log.Printf("OAUTH2_TOKEN_URL: %s", config.Oauth2TokenURL)

	// Parse the private key from Config.PrivateKey and store it in Config.PrivateKeyVal
	privateKey, err := parsePrivateKey()
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	config.PrivateKeyVal = privateKey

	// Generate and log the JWT, this is just for debugging purposes as this
	// implementation is not complete and is a work in progress
	jwtToken, err := generateJWT()
	if err != nil {
		log.Fatalf("Error generating JWT: %v", err)
	}
	log.Printf("Generated JWT: %s", jwtToken)

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
