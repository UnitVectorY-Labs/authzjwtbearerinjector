[![GitHub release](https://img.shields.io/github/release/UnitVectorY-Labs/authzjwtbearerinjector.svg)](https://github.com/UnitVectorY-Labs/authzjwtbearerinjector/releases/latest) [![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active) [![Go Report Card](https://goreportcard.com/badge/github.com/UnitVectorY-Labs/authzjwtbearerinjector)](https://goreportcard.com/report/github.com/UnitVectorY-Labs/authzjwtbearerinjector)

# authzjwtbearerinjector

A gRPC-based [ExtAuthz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) service for [Envoy Proxy](https://www.envoyproxy.io/) that implements the [jwt-bearer flow](https://datatracker.ietf.org/doc/html/rfc7523), injecting authentication credentials to backend services.

## Overview

The purpose of this service is to request JWT tokens to send to backend services through the use of an Envoy Proxy ExtAuthz service. It specifically implements the JWT-bearer flow with a private key used to sign a JWT token, which is then used in an OAuth 2.0 JWT-bearer flow to request a new token from the server. This new token is injected as the Authorization Bearer token in requests to the backend service.

This service is implemented in Go and is intended to run as a sidecar to the Envoy Proxy. It is configured to listen on a specific port, 50051 by default, for gRPC requests from the Envoy Proxy and then make requests to the OAuth 2.0 server to get the JWT token to inject into the request to the backend service.

## Usage

The latest `authzjwtbearerinjector` Docker image is available for deployment from GitHub Packages at [ghcr.io/unitvectory-labs/authzjwtbearerinjector](https://github.com/UnitVectorY-Labs/authzjwtbearerinjector/pkgs/container/authzjwtbearerinjector). This service is designed to run as a sidecar to Envoy Proxy. You can deploy this container alongside Envoy and configure Envoy to point to the `authzjwtbearerinjector` using the ExtAuthz filter, as described in the configuration section. The primary use case is to manage authentication with an RSA private key by generating JWTs to securely communicate with other services.

## Configuration

There are multiple ways to configure `authzjwtbearerinjector` using a YAML configuration file, environment variables, or Envoy Proxy route metadata.  If the same configuration parameter is provided multiple ways the following order of precedence is used: configuration file used first, environment variables overwrite configuration file, and route metadata overwrites everything else.

The config YAML file by default is loaded in from `/app/config.yaml` in the Docker image and can be injected into that location.  The location of the config file can be overridden by setting an alternative path to the environment variable `CONFIG_FILE_PATH`.

The following parameters must be configured with either the YAML configuration or environment variables and are mandatory for the service to start.

| YAML Parameter         | Environment Variable    | Description                                                            |
|------------------------|-------------------------|------------------------------------------------------------------------|
| `private_key`          | `PRIVATE_KEY`           | The private key used to sign the JWT token in PEM format.              |
| `oauth_token_url`      | `OAUTH2_TOKEN_URL`      | The URL of the OAuth 2.0 server to request the JWT token.              |
| `oauth_response_field` | `OAUTH2_RESPONSE_FIELD` | The field in the OAuth 2.0 server response to use as the Bearer token. |

The jwt-bearer flows are used by this application and the JWT that is locally constructed can be customized using the various configuration methods. Keep in mind the JWT described here is the one that is signed locally and sent to the OAuth endpoint, not the one that is injected into the request to the backend service.

The JWT Header by default will include the following claims which cannot be changed.

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

Additional claims can be added to the header using one of the following methods.

The YAML configuration file will inject all attributes under the `token_header` attribute as an array.  The environment variables are set with the prefix of `TOKEN_HEADER_` followed by the claim name that is case sensitive.  For metadata the namespace used is `com.unitvectory.authzjwtbearerinjector.tokenheader` with the claims as values.

The field that is most likely mandatory is setting the kid for the private key.  The example for this using each of the options are shown as follows for the Key ID of `0000000000000000000000000000000000000000`.

YAML configuration:

```yaml
token_header:
  kid: 0000000000000000000000000000000000000000
```

Environment Variable:

```bash
export TOKEN_HEADER_kid=0000000000000000000000000000000000000000
```

The metadata for the route in the Envoy Proxy configuration:

```yaml
metadata:
  filter_metadata:
    com.unitvectory.authzjwtbearerinjector.tokenheader:
      kid: 0000000000000000000000000000000000000000
```

It is worth emphasizing that if the same data is used for every request, such as Key ID, it is best to not set this using the Envoy Proxy metadata and instead prefer the YAML configuration or environment variables.

The JWT Payload by default will include the following claims which cannot be changed.  The `iat` claim will be populated with the current timestamp and the `exp` claim will be populated with the current timestamp plus 1 hour, this cannot be changed or overridden.

```json
{
  "exp": 1728346210,
  "iat": 1728342610
}
```

The YAML configuration file will inject all attributes under the `token_payload` attribute as an array.  The environment variables are set with the prefix of `TOKEN_PAYLOAD_` followed by the claim name that is case sensitive.  For metadata the namespace used is `com.unitvectory.authzjwtbearerinjector.tokenpayload` with the claims as values.

These are set the same way as the header claims.  The payload attributes `iss`, `sub`, and `aud` are most likely required by an implementation but any arbitrary claim can be included.  A special string can be set as the value of `${{UUID}}` which will be replaced with a randomly generated UUID.  This is useful for claims such as `jti`.

YAML configuration:

```yaml
token_payload:
  iss: https://issuer.example.com
  sub: https://subject.example.com
  aud: https://audience.example.com
  jti: ${{UUID}}
```

Environment Variable:

```bash
export TOKEN_PAYLOAD_iss=https://issuer.example.com
export TOKEN_PAYLOAD_sub=https://subject.example.com
export TOKEN_PAYLOAD_aud=https://audience.example.com
export TOKEN_PAYLOAD_jti=${{UUID}}
```

The metadata for the route in the Envoy Proxy configuration:

```yaml
metadata:
  filter_metadata:
    com.unitvectory.authzjwtbearerinjector.tokenpayload:
      iss: https://issuer.example.com
      sub: https://subject.example.com
      aud: https://audience.example.com
      jti: ${{UUID}}
```

The actual HTTP POST sent to the OAuth 2.0 server must have its payload fully configured as no default payload is specified. A special string must be set of `${{JWT}}` which will be replaced with the locally signed JWT token.  This is necessary for the `assertion` field in the OAuth 2.0 jwt-bearer flow as shown in the example.

YAML configuration:

```yaml
oauth_request:
  grant_type: urn:ietf:params:oauth:grant-type:jwt-bearer
  assertion: ${{JWT}}
```

Environment Variable:

```bash
export OAUTH_REQUEST_grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
export OAUTH_REQUEST_assertion=${{JWT}}
```

The metadata for the route in the Envoy Proxy configuration:

```yaml
metadata:
  filter_metadata:
    com.unitvectory.authzjwtbearerinjector.oauthrequest:
      grant_type: urn:ietf:params:oauth:grant-type:jwt-bearer
      assertion: ${{JWT}}
```

Additional or alternate parameters can be used such as `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and additional parameters can be included such as client_id and other standard or even non-standard OAuth parameters.

## Token Caching

Tokens requested by the service are cached for their entire lifetime. However, a soft expiration mechanism refreshes the token before it fully expires, defaulting to 50% of its lifespan. This default behavior can be customized using the YAML configuration `soft_token_lifetime` or the environment variable `SOFT_TOKEN_LIFETIME`. The value is optional and must be a decimal between 0 and 1, representing the percentage of the token's validity period. For example a default token lifetime of 1 hour with a soft token lifetime of 0.5 would refresh the token every 30 minutes assuming a request was made. Tokens are not proactively refreshed.

Tokens are cached based on the combination of input parameters provided to the service via Envoy Proxy route metadata, ensuring the correct JWT is returned. If a token has passed its soft expiration period, it will be refreshed on the next request. If the refresh fails and the token is still valid, the previously cached token will be returned.

## Optional Configuration

The following is a summary of the optional configurations that can be set.

| YAML Parameter         | Environment Variable    | Description                                                            |
|------------------------|-------------------------|------------------------------------------------------------------------|
| `soft_token_lifetime`  | `SOFT_TOKEN_LIFETIME`   | The percentage of the token's validity period before it is refreshed.  |
| N/A                    | `CONFIG_FILE_PATH`      | The path to the configuration file.                                    |

## Envoy Proxy Configuration

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
    - com.unitvectory.authzjwtbearerinjector.tokenheader
    - com.unitvectory.authzjwtbearerinjector.tokenpayload
    - com.unitvectory.authzjwtbearerinjector.oauthrequest
    grpc_service:
    google_grpc:
        target_uri: "127.0.0.1:50051"
        stat_prefix: ext_authz
    timeout: 5s
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
    com.unitvectory.authzjwtbearerinjector.tokenpayload:
      target_audience: https://app.example.com
```

## Google Service Account for Cloud Run Example

The following is a complete example of a `authzjwtbearerinjector` YAML configuration file for a Google Service Account used to get an identity token to send to the backend. It is worth emphasizing this approach is not recommended for Google Service Accounts as they have a built-in mechanism to get identity tokens. This is only an example of how to configure the service to work with a Google Service Account for environments outside of GCP that would use an identity token to authenticate to a backend service such as a Google Cloud Run service utilizing Envoy Proxy.

```yaml
# Replace with the private key for your service account
private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQE
  ...
  -----END PRIVATE KEY-----

token_header:
  kid: 0000000000000000000000000000000000000000 # Replace with the private_key_id for your service account

token_payload:
  iss: example-service-account@your-project-id.iam.gserviceaccount.com # Replace with your service account email
  sub: example-service-account@your-project-id.iam.gserviceaccount.com # Replace with your service account email
  aud: https://oauth2.googleapis.com/token
  target_audience: https://example.com # Specify the desired audience for the identity token

oauth_request:
  grant_type: urn:ietf:params:oauth:grant-type:jwt-bearer
  assertion: ${{JWT}}

oauth_token_url: https://oauth2.googleapis.com/token
oauth_response_field: id_token
```

The following is an example of a minimal Envoy Proxy configuration that uses the `authzjwtbearerinjector` service to get an identity token for a Google Service Account to send to a Google Cloud Run service.  This example uses the domain `example.com` and the backend service is listening on port 443.  The intent of this example is to have this backend domain be a service hosted on Cloud Run protected by a GCP Service Account.  The `target_audience` is set in the metadata which means it does not need to be set in the configuration file as shown in the above example, this is specifically useful as multiple routes can have different audiences generated for different backend services.

```yaml
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
              - "*"  # Match all domains
              routes:
              - match:
                  prefix: "/"  # Match all paths
                route:
                  cluster: backend
                  host_rewrite_literal: example.com
                metadata:
                  filter_metadata:
                    com.unitvectory.authzjwtbearerinjector.tokenpayload:
                      target_audience: https://example.com # Specify the desired audience for the identity token
          http_filters:
          - name: envoy.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              failure_mode_allow: false
              allowed_headers:
                patterns:
                  - exact: ''
              route_metadata_context_namespaces:
                - com.unitvectory.authzjwtbearerinjector.tokenheader
                - com.unitvectory.authzjwtbearerinjector.tokenpayload
                - com.unitvectory.authzjwtbearerinjector.oauthrequest
              grpc_service:
                google_grpc:
                  target_uri: "127.0.0.1:50051"
                  stat_prefix: ext_authz
                timeout: 5s
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: backend
    connect_timeout: 10s
    type: LOGICAL_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: backend
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: example.com
                port_value: 443
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: example.com
        common_tls_context:
          tls_params:
            tls_minimum_protocol_version: TLSv1_2
```

This Envoy Proxy configuration is used to demonstrate how to configure `authzjwtbearerinjector` with ExtAuthz and does not include all the necessary configuration for a production deployment.  The configuration should be customized to fit the specific needs of the deployment.

## Limitations

- Timeouts for token exchange is set to timeout after 5 seconds. Envoy proxy configuration should be set to match.
- Local JWT signing algorithm only supports RS256 as indicated by the `alg` claim in the header.
- The `exp` claim in the payload is set to 1 hour from the current time and cannot be changed.
- The `iat` claim in the payload is set to the current time and cannot be changed.
- Claims added to JWT header and payload are limited to strings as loaded from the configuration.
