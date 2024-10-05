package main

import (
	"context"
	"log"
	"net"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

type authServer struct {
	pb.UnimplementedAuthorizationServer
}

func (a *authServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
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
							Value: "Bearer TODO",
						},
					},
				},
			},
		},
	}

	return response, nil
}

func main() {
	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, &authServer{})

	log.Printf("gRPC ExtAuthz service listening on :50051...")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
