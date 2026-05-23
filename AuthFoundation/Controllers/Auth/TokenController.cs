using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// トークン発行処理を提供します。
    /// </summary>
    [ApiController]
    [Route("token")]
    [Route("api/auth/token")]
    public class TokenController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly OidcSigningService _oidcSigningService;

        /// <summary>
        /// <see cref="TokenController"/> の新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="dbContext">DB コンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="oidcSigningService">OIDC 署名サービス</param>
        public TokenController(OsolabAuthContext dbContext, IRedisClient redis, OidcSigningService oidcSigningService)
        {
            _dbContext = dbContext;
            _redis = redis;
            _oidcSigningService = oidcSigningService;
        }

        /// <summary>
        /// トークンエンドポイント処理を実行し、アクセストークンおよびリフレッシュトークンを返却します。
        /// </summary>
        /// <returns>トークン発行結果</returns>
        [HttpPost]
        public async Task<IActionResult> PostToken()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                string clientId = ValidateClient(input);
                TokenIssueResult issued = string.Equals(input.GrantType, Input.GrantTypeAuthorizationCode, StringComparison.Ordinal)
                    ? await ExchangeAuthorizationCodeAsync(input, clientId)
                    : await ExchangeRefreshTokenAsync(input, clientId);

                SetNoStoreHeaders(Response);
                if (string.IsNullOrWhiteSpace(issued.IdToken))
                {
                    return Ok(new
                    {
                        response_code = Code.SUCCESS.InternalCode,
                        access_token = issued.AccessToken,
                        refresh_token = issued.RefreshToken,
                        token_type = Code.AccessToken.TOKEN_TYPE_BEARER,
                        expires_in = AppConfig.AccessTokenExpireSec,
                        refresh_token_expires_in = AppConfig.RefreshTokenExpireSec,
                        scope = issued.Scope
                    });
                }

                return Ok(new
                {
                    response_code = Code.SUCCESS.InternalCode,
                    access_token = issued.AccessToken,
                    refresh_token = issued.RefreshToken,
                    token_type = Code.AccessToken.TOKEN_TYPE_BEARER,
                    expires_in = AppConfig.AccessTokenExpireSec,
                    refresh_token_expires_in = AppConfig.RefreshTokenExpireSec,
                    scope = issued.Scope,
                    id_token = issued.IdToken
                });
            }
            catch (ApiException ex)
            {
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.StatusCode
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }

        /// <summary>
        /// レスポンスにキャッシュ無効ヘッダーを設定します。
        /// </summary>
        /// <param name="response">HTTP レスポンス</param>
        private static void SetNoStoreHeaders(HttpResponse response)
        {
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["Pragma"] = "no-cache";
        }

        /// <summary>
        /// リクエストのクライアント認証情報を検証し、認証済みクライアントIDを返却します。
        /// </summary>
        /// <param name="input">トークン入力</param>
        /// <returns>認証済みクライアントID</returns>
        private string ValidateClient(Input input)
        {
            if (!string.IsNullOrWhiteSpace(input.BasicClientId))
            {
                if (!string.IsNullOrWhiteSpace(input.ClientId) && !string.Equals(input.ClientId, input.BasicClientId, StringComparison.Ordinal))
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
                }

                client_master client = Helper.CertClient(_dbContext, input.BasicClientId);
                if (!Helper.IsSameValue(client.client_secret, input.BasicClientSecret ?? string.Empty))
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
                }

                return input.BasicClientId;
            }

            if (string.IsNullOrWhiteSpace(input.ClientId))
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
            }

            Helper.CertClient(_dbContext, input.ClientId);
            return input.ClientId;
        }

        /// <summary>
        /// 認可コードグラントを検証し、トークンを発行します。
        /// </summary>
        /// <param name="input">トークン入力</param>
        /// <param name="clientId">検証済みクライアントID</param>
        /// <returns>発行したトークン情報</returns>
        private async Task<TokenIssueResult> ExchangeAuthorizationCodeAsync(Input input, string clientId)
        {
            AuthCodeSession codeSession = new AuthCodeSession();
            string? raw = await codeSession.ReadValueFromRedisAsync(_redis, input.AuthorizationCode);
            if (string.IsNullOrWhiteSpace(raw) || !codeSession.SetValue(raw))
            {
                throw new ApiException(Code.INVALID_AUTH_CODE, "invalid grant");
            }

            if (!string.Equals(codeSession.ClientId, clientId, StringComparison.Ordinal))
            {
                throw new ApiException(Code.INVALID_AUTH_CODE, "invalid grant");
            }

            if (!string.Equals(codeSession.RedirectUri, input.RedirectUri, StringComparison.Ordinal))
            {
                throw new ApiException(Code.ILLEGAL_REDIRECT_URI, Code.ILLEGAL_REDIRECT_URI.ErrorDescription);
            }

            if (!IsPkceValid(input.CodeVerifier, codeSession.CodeChallenge, codeSession.CodeChallengeMethod))
            {
                throw new ApiException(Code.INVALID_AUTH_CODE, "invalid grant");
            }

            string accessToken = $"{codeSession.OsolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
            string refreshToken = $"{codeSession.OsolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";

            await PersistTokenSessionsAsync(codeSession.OsolabId, clientId, codeSession.Scope, accessToken, refreshToken);
            string idToken = await _oidcSigningService.CreateIdTokenAsync(codeSession, Helper.ParseScopes(codeSession.Scope));
            await codeSession.DeleteSessionAsync(_redis);

            return new TokenIssueResult(accessToken, refreshToken, codeSession.Scope, idToken);
        }

        /// <summary>
        /// リフレッシュトークングラントを検証し、トークンを再発行します。
        /// </summary>
        /// <param name="input">トークン入力</param>
        /// <param name="clientId">検証済みクライアントID</param>
        /// <returns>再発行したトークン情報</returns>
        private async Task<TokenIssueResult> ExchangeRefreshTokenAsync(Input input, string clientId)
        {
            RefreshTokenSession refreshTokenSession = new RefreshTokenSession();
            string? raw = await refreshTokenSession.ReadValueFromRedisAsync(_redis, input.RefreshToken);
            if (string.IsNullOrWhiteSpace(raw) || !refreshTokenSession.SetValue(raw))
            {
                throw new ApiException(Code.INVALID_AUTH_CODE, "invalid grant");
            }

            if (!string.Equals(refreshTokenSession.ClientId, clientId, StringComparison.Ordinal))
            {
                throw new ApiException(Code.INVALID_AUTH_CODE, "invalid grant");
            }

            string accessToken = $"{refreshTokenSession.OsolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
            string rotatedRefreshToken = $"{refreshTokenSession.OsolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";

            await _redis.DeleteAsync(
                RefreshTokenSession.GetRedisKey(refreshTokenSession.RefreshToken),
                Code.RedisDbNo.REFRESH_TOKEN);
            await PersistTokenSessionsAsync(
                refreshTokenSession.OsolabId,
                clientId,
                refreshTokenSession.Scope,
                accessToken,
                rotatedRefreshToken);

            return new TokenIssueResult(accessToken, rotatedRefreshToken, refreshTokenSession.Scope);
        }

        /// <summary>
        /// アクセストークンセッションとリフレッシュトークンセッションを Redis に保存します。
        /// </summary>
        /// <param name="osolabId">ユーザーID</param>
        /// <param name="clientId">クライアントID</param>
        /// <param name="scope">スコープ</param>
        /// <param name="accessToken">アクセストークン</param>
        /// <param name="refreshToken">リフレッシュトークン</param>
        private async Task PersistTokenSessionsAsync(string osolabId, string clientId, string scope, string accessToken, string refreshToken)
        {
            AccessTokenSession accessTokenSession = new AccessTokenSession
            {
                AccessToken = accessToken,
                OsolabId = osolabId,
                ClientId = clientId,
                Scope = scope
            };
            await accessTokenSession.CreateSession(_redis);

            RefreshTokenSession refreshTokenSession = new RefreshTokenSession
            {
                RefreshToken = refreshToken,
                OsolabId = osolabId,
                ClientId = clientId,
                Scope = scope
            };
            await refreshTokenSession.CreateSession(_redis);
        }

        /// <summary>
        /// PKCE 検証値を算出し、リクエストの code_verifier が有効か判定します。
        /// </summary>
        /// <param name="verifier">code_verifier</param>
        /// <param name="challenge">code_challenge</param>
        /// <param name="method">code_challenge_method</param>
        /// <returns>検証結果</returns>
        private static bool IsPkceValid(string verifier, string challenge, string method)
        {
            if (!string.Equals(method, "S256", StringComparison.Ordinal))
            {
                return false;
            }

            byte[] bytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
            string calculated = Base64UrlEncode(bytes);
            return Helper.IsSameValue(calculated, challenge);
        }

        /// <summary>
        /// バイト列を Base64URL 文字列へ変換します。
        /// </summary>
        /// <param name="data">変換対象データ</param>
        /// <returns>Base64URL 文字列</returns>
        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>
        /// /token リクエスト入力を表します。
        /// </summary>
        public sealed class Input
        {
            public string FlowType { get; set; } = string.Empty;
            public string GrantType { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public string AuthorizationCode { get; set; } = string.Empty;
            public string RefreshToken { get; set; } = string.Empty;
            public string CodeVerifier { get; set; } = string.Empty;
            public string RedirectUri { get; set; } = string.Empty;
            public string? BasicClientId { get; set; }
            public string? BasicClientSecret { get; set; }

            public const string GrantTypeAuthorizationCode = "authorization_code";
            public const string GrantTypeRefreshToken = "refresh_token";

            /// <summary>
            /// HTTP リクエストからトークン入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>トークン入力</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);

                IFormCollection form = await request.ReadFormAsync();

                string? basicClientId = null;
                string? basicClientSecret = null;
                string authorization = request.Headers.Authorization.ToString();
                if (authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    string encoded = authorization["Basic ".Length..].Trim();
                    string decoded;
                    try
                    {
                        decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                    }
                    catch
                    {
                        throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
                    }

                    string[] parts = decoded.Split(':', 2);
                    if (parts.Length == 2)
                    {
                        basicClientId = parts[0];
                        basicClientSecret = parts[1];
                    }
                    else
                    {
                        throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
                    }
                }

                return new Input
                {
                    FlowType = request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key].ToString(),
                    GrantType = form["grant_type"].ToString(),
                    ClientId = form["client_id"].ToString(),
                    AuthorizationCode = form["code"].ToString(),
                    RefreshToken = form["refresh_token"].ToString(),
                    CodeVerifier = form["code_verifier"].ToString(),
                    RedirectUri = form["redirect_uri"].ToString(),
                    BasicClientId = basicClientId,
                    BasicClientSecret = basicClientSecret
                };
            }

            /// <summary>
            /// トークン入力の必須項目と形式を検証します。
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(FlowType, Code.HttpHeaders.X_FLOW_TYPE.Key);
                ValidateUtil.FormatParam(FlowType, Code.HttpHeaders.X_FLOW_TYPE.Key, Code.HttpHeaders.X_FLOW_TYPE.Regex);
                ValidateUtil.IndispensableParam(GrantType, Code.HttpBodies.GRANT_TYPE.Key);
                ValidateUtil.FormatParam(GrantType, Code.HttpBodies.GRANT_TYPE.Key, Code.HttpBodies.GRANT_TYPE.Regex);

                if (string.IsNullOrWhiteSpace(BasicClientId))
                {
                    ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                    ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
                }

                if (string.Equals(GrantType, GrantTypeAuthorizationCode, StringComparison.Ordinal))
                {
                    ValidateUtil.IndispensableParam(AuthorizationCode, Code.HttpBodies.AUTH_CODE.Key);
                    ValidateUtil.FormatParam(AuthorizationCode, Code.HttpBodies.AUTH_CODE.Key, Code.HttpBodies.AUTH_CODE.Regex);
                    ValidateUtil.IndispensableParam(CodeVerifier, Code.HttpBodies.CODE_VERIFIER.Key);
                    ValidateUtil.FormatParam(CodeVerifier, Code.HttpBodies.CODE_VERIFIER.Key, Code.HttpBodies.CODE_VERIFIER.Regex);
                    ValidateUtil.IndispensableParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key);
                    ValidateUtil.FormatParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key, Code.HttpQueries.REDIRECT_URI.Regex);
                    return;
                }

                ValidateUtil.IndispensableParam(RefreshToken, Code.HttpBodies.REFRESH_TOKEN.Key);
                ValidateUtil.FormatParam(RefreshToken, Code.HttpBodies.REFRESH_TOKEN.Key, Code.HttpBodies.REFRESH_TOKEN.Regex);
            }
        }

        private readonly record struct TokenIssueResult(
            string AccessToken,
            string RefreshToken,
            string Scope,
            string IdToken = "");

        private sealed class ErrorOutput
        {
            public string response_code { get; }
            public string message { get; }
            public string error { get; }
            public string error_description { get; }

            /// <summary>
            /// API 例外からエラー出力を生成します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public ErrorOutput(ApiException ex)
            {
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
                error = ToOAuthError(ex);
                error_description = ex.ErrorDescription;
            }

            /// <summary>
            /// API 例外を OAuth エラーコードへ変換します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            /// <returns>OAuth エラーコード</returns>
            private static string ToOAuthError(ApiException ex)
            {
                if (string.Equals(ex.InternalCode, Code.ILLEGAL_CLIENT.InternalCode, StringComparison.Ordinal))
                {
                    return "invalid_client";
                }

                if (string.Equals(ex.InternalCode, Code.INVALID_AUTH_CODE.InternalCode, StringComparison.Ordinal)
                    || string.Equals(ex.InternalCode, Code.ILLEGAL_REDIRECT_URI.InternalCode, StringComparison.Ordinal))
                {
                    return "invalid_grant";
                }

                if (string.Equals(ex.InternalCode, Code.REQUEST_PARAMETER_ERROR.InternalCode, StringComparison.Ordinal))
                {
                    return "invalid_request";
                }

                if (string.Equals(ex.InternalCode, Code.INTERNAL_SERVER_ERROR.InternalCode, StringComparison.Ordinal))
                {
                    return "server_error";
                }

                return "invalid_request";
            }
        }
    }
}
