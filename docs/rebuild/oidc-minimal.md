# 最低限OIDC Authorization Code + PKCE移植設計

## 目的

Authorization Code + PKCE の最小フローを、レビューしやすい粒度で移植する。

この段階では本番用DB/Redis永続化、永続的なJWKS管理、UserInfoの細かいscope制御は対象外にする。後続PRでDB/Redis/JWKS/UserInfoを分離して追加するため、まずはプロトコル境界とAPI形状を固定する。

## 対象

- `GET /authorize`
- `POST /login`
- `POST /token`
- 認可リクエストの一時保存
- 認可コードの一時保存
- PKCE S256検証
- RS256 ID Token発行

## 一時的な制約

- client/user は `appsettings` 由来の開発用インメモリ設定を使う。
- signing key はプロセス内生成とする。
- JWKS公開、UserInfo、DB/Redis永続化は後続PRで移植する。

## フロー

1. RP が `/authorize` に `response_type=code` と PKCE パラメータを送る。
2. AuthFoundation が認可リクエストを一時保存し、ログインURLを返す。
3. Portal が `/login` に `email`、`password`、`request_id` を送る。
4. AuthFoundation が認証後に authorization code を発行し、`redirect_uri` へ戻すURLを返す。
5. RP が `/token` に `code` と `code_verifier` を送る。
6. AuthFoundation が PKCE を検証し、`access_token` と `id_token` を返す。

## インターフェース

### GET /authorize

Required query:

- `response_type = code`
- `client_id`
- `redirect_uri`
- `scope`
- `state`
- `nonce`
- `code_challenge_method = S256`
- `code_challenge`

Success response for API tester / Portal integration:

```http
HTTP/1.1 200 OK
Set-Cookie: AuthRequestId=...
Content-Type: application/json
```

```json
{
  "redirect_url": "https://portal.osolab-auth.jp/login"
}
```

When `x-auth-ui-response-mode` is not `json`, the endpoint redirects to the login URL.

Validation errors:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
```

```json
{
  "response_code": "00002",
  "error_code": "00002",
  "message": "illegal client",
  "error": "invalid_client",
  "error_description": "illegal client"
}
```

### POST /login

Required form:

- `email`
- `password`
- `request_id`

`request_id` can be omitted only when `AuthRequestId` cookie exists.

Success response:

```http
HTTP/1.1 200 OK
Location: http://localhost:5700/callback?code=...&state=...
Content-Type: application/json
```

```json
{
  "result": "redirect",
  "redirect_url": "http://localhost:5700/callback?code=...&state=..."
}
```

Authentication failure:

```http
HTTP/1.1 401 Unauthorized
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

### POST /token

Required form:

- `grant_type = authorization_code`
- `client_id`
- `code`
- `code_verifier`
- `redirect_uri`

Success response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "access_token": "dev_...",
  "id_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email"
}
```

Invalid code, client, redirect URI, or PKCE verifier:

```http
HTTP/1.1 400 Bad Request
Cache-Control: no-store
Pragma: no-cache
Content-Type: application/json
```

```json
{
  "response_code": "00001",
  "error_code": "00001",
  "message": "invalid token request",
  "error": "invalid_grant",
  "error_description": "invalid token request"
}
```

## Validation

- `dotnet build`
- `dotnet test`
- Unit tests cover all response codes and response fields defined in this design.
