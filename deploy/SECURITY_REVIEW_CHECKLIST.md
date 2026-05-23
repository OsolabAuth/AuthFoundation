# Security Review Checklist

Last updated: 2026-05-23
Related issue: #13

## Authentication / Authorization

| Item | Status | Notes |
|---|---|---|
| PKCE (`S256`) required on `/authorize` | Done | `AuthorizeController.Input.Validate` |
| `state` required and returned | Done | `/authorize` + `/token` flow |
| Redirect URI exact-match + fragment reject | Done | `Helper.CertAuthorizeClient` |
| OAuth error fields on auth endpoints | Done | `error` / `error_description` added |
| `no-store`/`no-cache` on auth responses | Done | major auth endpoints |

## Session / Cookie

| Item | Status | Notes |
|---|---|---|
| HttpOnly session cookies | Done | session cookies all HttpOnly |
| SameSite cross-origin behavior | Done | cross-origin HTTPS => `SameSite=None;Secure` |
| Legacy cookie fallback compatibility | Done | `AuthRequestSessionId` + `session_id` |
| Session fixation review | Partial | login/session rotation behavior should be reviewed continuously |

## Token Handling

| Item | Status | Notes |
|---|---|---|
| Access token/revoke endpoint present | Done | `/revoke` implemented |
| Logout token cleanup | Done | `/logout` deletes access token when bearer provided |
| UserInfo invalid token handling | Done | 401 + `WWW-Authenticate` |
| JWK multi-instance sync behavior | Done | `OidcSigningService` reloads active keys by `JwkSigningKeyReloadSec` |
| Refresh token rotation | Done | `/token` supports `grant_type=refresh_token` and rotates refresh token on each exchange |

## Input Validation

| Item | Status | Notes |
|---|---|---|
| Email format strict validation | Done | `ValidateUtil.EmailParam` + UT |
| Password regex validation | Done | login/signup endpoints |
| Session ID format validation | Done | form/header/cookie resolution paths |
| Term consent input validation | Done | `accepted` + `term_ids` flow |

## Mail / Secrets

| Item | Status | Notes |
|---|---|---|
| Gmail SMTP migration | Done | `GmailSmtpMail` |
| SMTP sender/recipient format guard | Done | runtime guard added |
| Secret existence preflight in deploy | Done | workflow checks secret versions |
| Required secret mapping completeness check | Done | deploy workflow required keys check |
| Secret max-age gate | Done | deploy workflow supports `CLOUD_RUN_SECRET_MAX_AGE_DAYS` |

## Remaining recommended actions

1. Operate threat-model review process using `deploy/THREAT_MODEL_AUTH.md` (periodic updates).
2. Configure/operate `CLOUD_RUN_SECRET_MAX_AGE_DAYS` in production CI variables.
