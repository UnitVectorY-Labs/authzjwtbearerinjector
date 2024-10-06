# authzjwtbearerinjector

A GRPC-based ExtAuthz service for Envoy Proxy that implements the JWT-bearer flow, injecting authentication credentials to backend services.

## Overview

The purpose of this service is to request JWT tokens to send to backend services through the use of an Envoy Proxy ExtAuthz service. It specifically implements the JWT-bearer flow with a private key used to sign a JWT token, which is then used in an OAuth 2.0 JWT-bearer flow to request a new token from the server. This new token is injected as the Authorization Bearer token in requests to the backend service.

This service is implemented in Go and is intended to run as a sidecar to the Envoy Proxy. It is configured to listen on a specific port for requests from the Envoy Proxy and then make requests to the OAuth 2.0 server to get the JWT token to inject into the request to the backend service.

## Configuration

There are three ways to configure the `authzjwtbearerinjector` service: using **context extensions**, **environment variables**, or a **configuration file**.

- **Context Extensions**: These are used to pass information specific to the request or backend.
- **Environment Variables and Configuration File**: These are used to pass static information for the service.

### Precedence

1. **Context Extensions**: Dynamic parameters specific to each request or backend can be passed in through Envoy's context extensions.
2. **Environment Variables**: Static configurations are set using environment variables.
3. **Configuration File**: A YAML configuration file can be used for easier management of static settings.

While none of the fields are required at startup (since they can be provided through context extensions), it is recommended to configure the service with environment variables or a configuration file to reduce the amount of information processed with each request.

### Envoy Proxy Configuration

The Envoy Proxy configuration uses ExtAuthz to call this service. The context extensions are passed to the service in the request and can be used to convey additional information.

```yaml
http_filters:
  - name: envoy.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      context_extensions:
        local_token_target_audience: "http://example.com"
      transport_api_version: V3
      failure_mode_allow: false
      grpc_service:
        google_grpc:
          target_uri: 127.0.0.1:50051
          stat_prefix: ext_authz
        timeout: 0.5s
```

### Environment Variables

To run `authzjwtbearerinjector`, you can provide the following environment variables:

- `PRIVATE_KEY`: The private key used to sign the JWT token.
- `LOCAL_TOKEN_iss`: The issuer of the token.
- `LOCAL_TOKEN_sub`: The subject of the token.
- `LOCAL_TOKEN_aud`: The audience of the token.
- `OAUTH2_TOKEN_URL`: The URL of the OAuth 2.0 token endpoint.
- `OAUTH2_RESPONSE_FIELD`: The field in the response from the OAuth 2.0 token endpoint that contains the token (e.g., `access_token` or `id_token`).

### Configuration File

Alternatively, you can provide a configuration file in YAML format with the following fields:

```yaml
private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEpAIBAAKCAQEA...
  -----END PRIVATE KEY-----

local_token:
  iss: "http://example.com"
  sub: "http://example.com"
  aud: "http://example.com"

oauth2:
  token_url: "http://example.com/token"
  response_field: "id_token"
```

### JWT Claims

The fields for the `local_token_` context extensions, `LOCAL_TOKEN_` environment variables, or `local_token` values in the configuration file are included as claims in the locally signed JWT token. While every implementation needs the `iss`, `sub`, and `aud` fields (which are required), additional fields can be added as needed for specific implementations.
