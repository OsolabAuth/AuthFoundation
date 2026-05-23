# AuthFoundation Threat Model (Draft)

Last updated: 2026-05-23  
Related issues: #13, #15

## Scope

- API endpoints in `AuthFoundation`:
  - `/authorize`, `/login`, `/signup/*`, `/terms`, `/token`, `/userinfo`, `/logout`, `/revoke`
- Runtime:
  - Cloud Run + SQL Server + Redis + Secret Manager
- Out-of-scope:
  - Portal frontend supply-chain risk
  - Identity proofing requirements beyond current OIDC flow

## Assets

1. Access tokens / refresh tokens / auth codes
2. Login sessions (`AuthSessionId`) and auth request sessions
3. User credentials (email/password hash)
4. Signing keys and JWK encryption key
5. SMTP credentials (Gmail app password)

## Trust Boundaries

1. Browser <-> Auth API (cross-origin cookie/API boundary)
2. Auth API <-> Redis (session/token state)
3. Auth API <-> SQL Server (persistent account/consent data)
4. Auth API <-> Secret Manager / runtime env (secret injection boundary)

## Threat Scenarios and Controls

| Threat | Current controls | Residual risk |
|---|---|---|
| Authorization code interception/replay | PKCE `S256` mandatory, redirect URI exact-match, no-store/no-cache | short auth code TTL is fixed; monitor abuse patterns |
| Refresh token replay after leak | `grant_type=refresh_token` rotation implemented, old refresh token invalidated | stolen latest refresh token can still be used until next rotation |
| Session fixation / stolen cookie | HttpOnly cookies, cross-origin `SameSite=None; Secure` for HTTPS, session id format validation | endpoint-level rotation cadence should be periodically reviewed |
| Open redirect / malicious callback | strict redirect URI policy (`https`, `localhost`, `osolab-*-local`), fragment reject, registry exact-match | registration governance depends on client onboarding process |
| SMTP credential misuse | Secret Manager mapping required, runtime address validation, runbook for rotation | mailbox compromise outside API control |
| Stale secret usage in production | deploy preflight checks for secret existence + required mapping + max-age gate (`CLOUD_RUN_SECRET_MAX_AGE_DAYS`) | if max-age variable is not configured, stale secrets may remain |
| Multi-instance signing key drift | JWK active-key reload by `JwkSigningKeyReloadSec` | brief overlap window before reload interval elapses |

## Required Operational Policies

1. Set `CLOUD_RUN_SECRET_MAX_AGE_DAYS` in GitHub Actions variables (recommended: `90`).
2. Rotate Gmail app password and JWK encryption key on a fixed schedule.
3. Keep `CLOUD_RUN_UPDATE_SECRETS` pinned to intended secret names (avoid accidental drift).
4. Periodically audit redirect URI registrations per client.

## Next Security Tasks

1. Add explicit replay-detection telemetry for refresh token exchange failures.
2. Add alerting for repeated `invalid_grant` on `/token`.
3. Review account lockout/rate-limit strategy for `/login` and `/signup/verify`.
