package main

import (
	"context"
	"crypto/rsa"
	"log"
	"net"
	"os"
	"strconv"
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
)

const (
	metadataTokenHeaderNamespace  = "com.unitvectory.authzjwtbearerinjector.tokenheader"
	metadataTokenPayloadNamespace = "com.unitvectory.authzjwtbearerinjector.tokenpayload"
	metadataOauthRequestNamespace = "com.unitvectory.authzjwtbearerinjector.oauthrequest"
)

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

	// Determine the port to listen on
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	// Validate the port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		log.Fatalf("invalid port: %v", port)
	}

	// Start the gRPC server
	lis, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, &authServer{})

	// Enable gRPC reflection
	reflection.Register(grpcServer)

	log.Printf("authzjwtbearerinjector service listening on :%s...", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {

	metadataTokenHeader := extractMetadataClaims(req, metadataTokenHeaderNamespace)
	metadataTokenPayload := extractMetadataClaims(req, metadataTokenPayloadNamespace)
	metadataOauthRequest := extractMetadataClaims(req, metadataOauthRequestNamespace)

	// Get the cached token
	start := time.Now()
	jwtToken, err := authz.GetCachedToken(config, privateKey, metadataTokenHeader, metadataTokenPayload, metadataOauthRequest)
	elapsed := time.Since(start)
	authz.DebugLog("getCachedToken took %s", elapsed)

	if err != nil {
		log.Printf("Error getting cached token: %v", err)
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

func extractMetadataClaims(req *pb.CheckRequest, namespace string) map[string]string {
	claims := make(map[string]string)
	filterMetadata := req.Attributes.GetRouteMetadataContext().GetFilterMetadata()
	if metadata, ok := filterMetadata[namespace]; ok {
		if fields := metadata.GetFields(); fields != nil {
			for key, value := range fields {
				claims[key] = value.GetStringValue()
			}
		}
	} else {
		authz.DebugLog("%s not found in filter metadata", namespace)
	}

	return claims
}
