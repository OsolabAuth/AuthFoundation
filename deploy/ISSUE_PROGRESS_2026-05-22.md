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

## Additional progress (2026-05-23)

1. #13 / #15 Input validation hardening for email
- Added `ValidateUtil.EmailParam` with strict `MailAddress.TryCreate` validation.
- Applied to:
  - `POST /login` input validation
  - `POST /signup/email` input validation
  - `PUT /inner/users/{osolabId}/claims` optional email validation
- Added UT:
  - `PostLogin_InvalidMailAddressFormat_ReturnsRequestParameterError`
  - `PostEmail_InvalidMailAddressFormat_ReturnsRequestParameterError`

2. #9 Redirect URI policy test reinforcement
- Added UT:
  - `CertAuthorizeClient_AllowsOnlyOsolabHyphenLocalPatternForHttp`
- Verifies allowlist behavior:
  - allow `http://osolab-*-local[:port]/...`
  - reject local-like but non-matching domains (`.local` style)

3. #15 Gmail SMTP operation docs
- Added `deploy/GMAIL_SMTP_RUNBOOK.md`:
  - app password rotation steps
  - post-rotation verification checklist
  - production log triage command

4. #15 Deploy preflight hardening for required runtime secrets
- Updated `.github/workflows/deploy-cloud-run.yml`:
  - Fails early when `CLOUD_RUN_UPDATE_SECRETS` is empty in deploy job.
  - Validates required secret mappings exist:
    - `ConnectionStrings__DefaultConnection`
    - `ConnectionStrings__Redis`
    - `PasswordHashKey`
    - `JwkPrivateKeyEncryptionKey`
    - `Mail__FromEmail`
    - `GmailSmtp__Username`
    - `GmailSmtp__AppPassword`

5. #15 Runtime SMTP error prevention
- Added sender/recipient mail format guards in `GmailSmtpMail.SendMailAsync`.
- Added UT:
  - `SendMailAsync_InvalidFromEmail_ThrowsInvalidOperationException`
  - `SendMailAsync_InvalidRecipientEmail_ThrowsInvalidOperationException`

6. #9 Redirect URI policy finalization
- Added `deploy/REDIRECT_URI_POLICY.md` documenting:
  - allowed schemes/hosts (`https`, `http://localhost`, `http://osolab-*-local`)
  - fragment prohibition
  - exact-match registration requirement
  - explicitly rejected URI patterns

7. #13 Security review tracking
- Added `deploy/SECURITY_REVIEW_CHECKLIST.md`:
  - implemented controls vs remaining actions
  - concrete follow-up list for CI E2E / refresh token policy / threat model

8. End-to-end smoke verification (controller-level)
- Added `AuthFoundationTest/AuthFlowSmokeTests.cs`:
  - `authorize -> login -> token -> userinfo -> logout` を1テストで検証
- Test result updated:
  - `dotnet test -c Debug` => 93 passed / 0 failed

9. #10 JWK scalability follow-up (multi-instance key sync)
- Added config key `JwkSigningKeyReloadSec` (default `300`) to control in-process signing key/JWKS reload cadence.
- Updated `OidcSigningService` to refresh active key set from DB when reload interval elapses.
  - Enables instance-local cache refresh without process restart.
  - Supports quicker cross-instance convergence when a newer active key is inserted.
- Added UT:
  - `CreateIdTokenAsync_WhenReloadIntervalNotElapsed_KeepsCachedSigningKey`
  - `CreateIdTokenAsync_WhenReloadIntervalZero_UsesLatestSigningKey`
- Test result updated:
  - `dotnet test -c Debug` => 95 passed / 0 failed

10. #13 Refresh token rotation policy implementation
- Extended `POST /token` to support `grant_type=refresh_token`.
- Implemented one-time refresh token rotation:
  - old refresh token is deleted on successful exchange
  - new access token + refresh token pair is issued
  - scope is inherited from refresh token session
- Added UT:
  - `PostToken_RefreshGrant_RotatesRefreshToken`
  - `PostToken_RefreshGrant_UnknownRefreshToken_ReturnsInvalidGrant`
  - `PostToken_RefreshGrant_ClientMismatch_ReturnsInvalidGrant`
- Test result updated:
  - `dotnet test -c Debug` => 98 passed / 0 failed

11. #13 Threat model and secret-rotation governance
- Added `deploy/THREAT_MODEL_AUTH.md` covering:
  - trust boundaries, threat scenarios, current controls, residual risks
  - mandatory operational policies and next security tasks
- Updated deploy workflow with optional secret age gate:
  - `CLOUD_RUN_SECRET_MAX_AGE_DAYS`
  - fails deploy when required runtime secrets are older than threshold
- Updated security checklist:
  - `Secret max-age gate` marked as Done
  - remaining items narrowed to operational rollout
