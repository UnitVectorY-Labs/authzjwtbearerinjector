# authzjwtbearerinjector

A GRPC-based ExtAuthz service for Envoy Proxy that implements the JWT-bearer flow, injecting authentication credentials to backend services.

## Overview

The purpose of this service is to request JWT tokens to send to backend services through the use of an Envoy Proxy ExtAuthz service. It specifically implements the JWT-bearer flow with a private key used to sign a JWT token, which is then used in an OAuth 2.0 JWT-bearer flow to request a new token from the server. This new token is injected as the Authorization Bearer token in requests to the backend service.

This service is implemented in Go and is intended to run as a sidecar to the Envoy Proxy. It is configured to listen on a specific port for requests from the Envoy Proxy and then make requests to the OAuth 2.0 server to get the JWT token to inject into the request to the backend service.

## Configuration

There are three ways to configure the `authzjwtbearerinjector` service: using **context metadata**, **environment variables**, or a **configuration file**.

- **Context Metadata**: These are used to pass information specific to the request or backend. Only supports local token claims for now.
- **Environment Variables and Configuration File**: These are used to pass static information for the service.

### Precedence

1. **Context Metadata**: Dynamic parameters specific to each request or backend can be passed in through Envoy's metdata. The namespace `com.unitvectory.authzjwtbearerinjector.localtoken` is used to pass these parameters.
2. **Environment Variables**: Static configurations are set using environment variables.
3. **Configuration File**: A YAML configuration file can be used for easier management of static settings.

While none of the fields are required at startup (since they can be provided through context extensions), it is recommended to configure the service with environment variables or a configuration file to reduce the amount of information processed with each request.

### Envoy Proxy Configuration

The Envoy Proxy configuration uses ExtAuthz to call this service. The context extensions are passed to the service in the request and can be used to convey additional information.

```yaml
- name: envoy.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    failure_mode_allow: false
    allowed_headers:
    patterns:
        - exact: ''
    route_metadata_context_namespaces:
    - com.unitvectory.authzjwtbearerinjector.localtoken
    grpc_service:
    google_grpc:
        target_uri: "127.0.0.1:50051"
        stat_prefix: ext_authz
    timeout: 1s
```

Then on each route the variables can be set in the metadata:

```yaml
routes:
- match:
    prefix: "/"
route:
    cluster: example_cluster
metadata:
    filter_metadata:
    com.unitvectory.authzjwtbearerinjector.localtoken:
        target_audience: "http://backend.example.com"
```

### Environment Variables

To run `authzjwtbearerinjector`, you can provide the following environment variables:

- `PRIVATE_KEY`: The private key used to sign the JWT token.
- `LOCAL_TOKEN_iss`: The issuer of the token.
- `LOCAL_TOKEN_sub`: The subject of the token.
- `LOCAL_TOKEN_aud`: The audience of the token.
- `OAUTH2_TOKEN_URL`: The URL of the OAuth 2.0 token endpoint.
- `OAUTH2_RESPONSE_FIELD`: The field in the response from the OAuth 2.0 token endpoint that contains the token (e.g., `access_token` or `id_token`).
- `SOFT_TOKEN_LIFETIME`: The percentage of the token lifetime to request a new token (e.g., `0.9` to request a new token when 90% of the token lifetime has passed). Default is `0.5`. If token request fails after the soft expiration has passed but before the hard expiration, the request will be retried with the previous token.

### Configuration File

Alternatively, you can provide a configuration file in YAML format with the following fields:

```yaml
private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEpAIBAAKCAQEA...
  -----END PRIVATE KEY-----

local_token:
  iss: "http://issuer.example.com"
  sub: "http://subject.example.com"
  aud: "http://audience.example.com"

oauth2:
  token_url: "http://oauth.example.com/token"
  response_field: "id_token"
```

The location of the configuration file is expected to be `/app/conig.yaml` by default, but this can be changed with the `CONFIG_FILE` environment variable.

### JWT Claims

The fields for the `local_token_` context extensions, `LOCAL_TOKEN_` environment variables, or `local_token` values in the configuration file are included as claims in the locally signed JWT token. While every implementation needs the `iss`, `sub`, and `aud` fields (which are required), additional fields can be added as needed for specific implementations.

## Limitations

- Signing Algorithm: Only RS256 is supported for signing the JWT token.
