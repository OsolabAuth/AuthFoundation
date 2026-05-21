# Issue Progress (2026-05-22)

Branch: `feat/issue-batch-20260522`

## Completed in this branch

1. #11 Login status API
- `GET /login/status` implemented
- Unit tests added

2. #12 Token revoke API
- `POST /revoke` implemented (`access_token` / `refresh_token` + `token_type_hint`)
- Client ownership check added
- Unit tests added

3. #17 OIDC response normalization (major part)
- Added `error` / `error_description` to error responses for:
  - `/token`
  - `/userinfo`
  - `/revoke`
  - `/logout`
  - `/authorize`
  - `/login`
  - `/terms`
- Added `Cache-Control: no-store` + `Pragma: no-cache` to the above auth endpoints
- Added `WWW-Authenticate` on `/userinfo` invalid token
- Expanded unit tests accordingly

4. #3 Deploy hardening (Cloud Run workflow)
- Resolved network flag conflict handling (`--clear-network` vs network/subnet/tags path)
- Added pre-deploy secret existence checks from `CLOUD_RUN_UPDATE_SECRETS`
- Added post-deploy Cloud Run service status output
- Added check that latest created revision is also latest ready revision

5. #2 / #3 operational docs update
- Added troubleshooting notes to deploy doc:
  - network flag conflict
  - missing secret failure
  - recommended secret mapping format

6. screen expired mitigation (portal cross-origin)
- Session cookie policy centralized in `Helper.BuildSessionCookieOptions`
- Cross-origin HTTPS requests now use `SameSite=None; Secure`
- Applied to:
  - `AuthRequestSessionId` cookie
  - `AuthSessionId` cookie
  - `signup_session_id` cookie
- Unit tests added

## Current test status

- `dotnet test` passed
- Latest result: **87 passed / 0 failed**

## Remaining high-priority items

1. #15 Gmail SMTP production validation
- Verify secret rotation/runbook and monitor delivery failures in production logs

2. #13 Security review
- Expand threat-model checklist coverage and document findings

3. #9 Redirect URI policy finalization
- Review and document localhost/custom local domain policy and constraints

4. End-to-end operational verification
- Full flow verification on production-like environment:
  - `authorize -> login/signup -> terms -> token -> userinfo -> logout`
