# AI Agent Delegated Auth Rebuild Design

## Goal

Add the first API-only implementation of delegated authentication for AI agents.

## Scope

- Create an agent owned by a user.
- Create a client-bound delegation with fixed scopes and expiration.
- Issue one-time `agent_secret` during creation.
- Exchange `agent_id` / `agent_secret` for short-lived agent tokens.
- Use `sub = agent_id` and include `owner_sub`.

## Endpoints

- `POST /agent`
- `POST /agent/token`

## Out of Scope

- Agent management UI
- Secret rotation
- Audit log persistence
- Manual pairing flow
- DPoP/JWK-bound agents

## Validation

- `dotnet build`
- `dotnet test`
