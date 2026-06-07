# Features Catalog API Rebuild Design

## Goal

Expose a lightweight endpoint that lets clients and API test scenarios confirm which public AuthFoundation features are implemented in the current build.

`GET /version` identifies the service and build status. `GET /features` complements it by returning the implemented feature catalog.

## Scope

- `GET /features`
- Static catalog of implemented public features
- No secrets, deployment settings, or per-environment capability flags
- Stable feature keys for client-side diagnostics and scenario selection

## Out of Scope

- Database-driven feature flags
- User-specific authorization checks
- Environment-specific enable/disable state
- Admin-only diagnostics

## Endpoint Contract

### GET /features

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "service": "AuthFoundation",
  "status": "ok",
  "features": [
    {
      "key": "oidc.authorization_code_pkce",
      "name": "Authorization Code + PKCE",
      "status": "available",
      "description": "OIDC authorization request, login, code issuance, and token exchange."
    }
  ]
}
```

Required top-level fields:

- `service`
- `status`
- `features`

Required feature fields:

- `key`
- `name`
- `status`
- `description`

## Implemented Feature Keys

- `service.version`
- `oidc.discovery`
- `oidc.authorization_code_pkce`
- `oidc.userinfo`
- `account.signup_terms`
- `mfa.step_up`
- `account.password_change`
- `account.password_reset`
- `session.logout_revoke`
- `account.withdrawal`
- `agent.delegated_auth`

## Validation

- `dotnet build AuthFoundation/AuthFoundation.csproj -c Debug`
- `dotnet test --project AuthFoundationTest/AuthFoundationTest.csproj -c Debug`
