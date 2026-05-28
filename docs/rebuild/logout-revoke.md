# Logout / Revoke Rebuild Design

## Goal

Add a minimal logout and token revocation surface before implementing stronger session management.

## Scope

- `POST /logout` clears the authorization request cookie.
- `POST /revoke` removes an issued development access token from the in-memory token store.
- UserInfo rejects revoked access tokens.

## Out of Scope

- Refresh token revocation
- Back-channel logout
- Front-channel logout iframe support
- Persistent session records

## Validation

- `dotnet build`
- `dotnet test`
