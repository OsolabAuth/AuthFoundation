# OIDC Discovery / JWKS / UserInfo Rebuild Design

## Goal

Expose the minimum standards-facing endpoints required by OIDC clients after the basic authorization code flow exists.

## Scope

- `GET /.well-known/openid-configuration`
- `GET /jwks`
- `GET /userinfo`
- RS256 public key material exposed through JWKS
- Bearer access token lookup from Redis-backed access token sessions

## Endpoint Contracts

### GET /.well-known/openid-configuration

Returns endpoint URLs derived from `AppConfig.Issuer`.

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

Required fields:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `response_types_supported`
- `grant_types_supported`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`
- `scopes_supported`
- `token_endpoint_auth_methods_supported`
- `code_challenge_methods_supported`
- `claims_supported`

### GET /jwks

Returns the active signing key as a JSON Web Key Set. The key is process-local for this rebuild phase and will be replaced by persisted signing keys later.

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

Each key must include:

- `kty = RSA`
- `use = sig`
- `kid`
- `alg = RS256`
- `n`
- `e`

### GET /userinfo

Accepts the access token issued by `/token` and returns the current user's `sub`, `email`, and `name`.

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "sub": "dev_user",
  "email": "demo@example.com",
  "name": "Demo User"
}
```

Missing, malformed, or unknown bearer token:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer
Content-Type: application/json
```

```json
{
  "response_code": "00008",
  "error_code": "00008",
  "message": "unauthorized",
  "error": "invalid_token",
  "error_description": "unauthorized"
}
```

## Out of Scope

- Persisted signing key rotation
- Refresh tokens
- Token introspection
- Pairwise subject identifiers
- Full claims/scope filtering beyond the development profile claims

## Validation

- `dotnet build`
- `dotnet test`
- Unit tests cover all response codes and response fields defined in this design.
