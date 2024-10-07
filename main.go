package main

import (
	"context"
	"crypto/rsa"
	"log"
	"net"
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
	metadataLocalTokenNamespace = "com.unitvectory.authzjwtbearerinjector.localtoken"
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

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {

	metadataClaims := extractMetadataClaims(req)

	// Get the cached token
	start := time.Now()
	jwtToken, err := authz.GetCachedToken(config, privateKey, metadataClaims)
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

func extractMetadataClaims(req *pb.CheckRequest) map[string]string {
	claims := make(map[string]string)
	filterMetadata := req.Attributes.GetRouteMetadataContext().GetFilterMetadata()
	if metadata, ok := filterMetadata[metadataLocalTokenNamespace]; ok {
		if fields := metadata.GetFields(); fields != nil {
			for key, value := range fields {
				claims[key] = value.GetStringValue()
			}
		}
	} else {
		authz.DebugLog("%s not found in filter metadata", metadataLocalTokenNamespace)
	}

	return claims
}
