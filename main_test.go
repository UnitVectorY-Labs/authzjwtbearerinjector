package main

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestExtractMetadataClaims_WithValidMetadata(t *testing.T) {
	namespace := "com.unitvectory.authzjwtbearerinjector.tokenheader"

	fields := map[string]*structpb.Value{
		"kid": structpb.NewStringValue("test-key-id"),
		"alg": structpb.NewStringValue("RS256"),
	}

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					namespace: {
						Fields: fields,
					},
				},
			},
		},
	}

	claims := extractMetadataClaims(req, namespace)

	if claims["kid"] != "test-key-id" {
		t.Errorf("expected kid='test-key-id', got: %s", claims["kid"])
	}
	if claims["alg"] != "RS256" {
		t.Errorf("expected alg='RS256', got: %s", claims["alg"])
	}
}

func TestExtractMetadataClaims_NamespaceNotFound(t *testing.T) {
	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{},
			},
		},
	}

	claims := extractMetadataClaims(req, "nonexistent.namespace")

	if len(claims) != 0 {
		t.Errorf("expected empty claims, got: %v", claims)
	}
}

func TestExtractMetadataClaims_NilMetadata(t *testing.T) {
	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{},
	}

	claims := extractMetadataClaims(req, "any.namespace")

	if len(claims) != 0 {
		t.Errorf("expected empty claims, got: %v", claims)
	}
}

func TestExtractMetadataClaims_EmptyFields(t *testing.T) {
	namespace := "com.unitvectory.authzjwtbearerinjector.tokenpayload"

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					namespace: {
						Fields: map[string]*structpb.Value{},
					},
				},
			},
		},
	}

	claims := extractMetadataClaims(req, namespace)

	if len(claims) != 0 {
		t.Errorf("expected empty claims, got: %v", claims)
	}
}

func TestCreateErrorResponse(t *testing.T) {
	resp := createErrorResponse()

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	// Check status code (13 = Internal)
	if resp.Status == nil {
		t.Fatal("expected non-nil status")
	}
	if resp.Status.Code != 13 {
		t.Errorf("expected status code 13, got: %d", resp.Status.Code)
	}
	if resp.Status.Message != "Internal server error" {
		t.Errorf("expected 'Internal server error', got: %s", resp.Status.Message)
	}

	// Check denied response
	denied, ok := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatal("expected DeniedResponse type")
	}
	if denied.DeniedResponse.Status.Code != envoy_type.StatusCode(500) {
		t.Errorf("expected HTTP 500, got: %d", denied.DeniedResponse.Status.Code)
	}
	if denied.DeniedResponse.Body != "Failed to request token" {
		t.Errorf("expected 'Failed to request token', got: %s", denied.DeniedResponse.Body)
	}
}

func TestExtractMetadataClaims_MultipleNamespaces(t *testing.T) {
	headerNamespace := "com.unitvectory.authzjwtbearerinjector.tokenheader"
	payloadNamespace := "com.unitvectory.authzjwtbearerinjector.tokenpayload"

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			RouteMetadataContext: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					headerNamespace: {
						Fields: map[string]*structpb.Value{
							"kid": structpb.NewStringValue("header-kid"),
						},
					},
					payloadNamespace: {
						Fields: map[string]*structpb.Value{
							"iss": structpb.NewStringValue("payload-issuer"),
						},
					},
				},
			},
		},
	}

	headerClaims := extractMetadataClaims(req, headerNamespace)
	payloadClaims := extractMetadataClaims(req, payloadNamespace)

	if headerClaims["kid"] != "header-kid" {
		t.Errorf("expected header kid, got: %s", headerClaims["kid"])
	}
	if payloadClaims["iss"] != "payload-issuer" {
		t.Errorf("expected payload iss, got: %s", payloadClaims["iss"])
	}
}
