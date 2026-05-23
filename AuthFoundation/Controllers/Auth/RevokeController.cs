using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// トークン失効処理を提供します。
    /// </summary>
    [ApiController]
    [Route("revoke")]
    [Route("api/auth/revoke")]
    public class RevokeController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        /// <summary>
        /// <see cref="RevokeController"/> の新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="dbContext">DB コンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        public RevokeController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        /// <summary>
        /// トークンを失効します。
        /// </summary>
        /// <returns>失効結果</returns>
        [HttpPost]
        public async Task<IActionResult> PostRevoke()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                string clientId = ValidateClient(input);
                await RevokeTokenAsync(input.TokenType, input.Token, clientId);
                SetNoStoreHeaders(Response);

                return Ok(new
                {
                    response_code = Code.SUCCESS.Code,
                    result = "revoked"
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
        /// クライアント認証情報を検証し、クライアントIDを返却します。
        /// </summary>
        /// <param name="input">失効入力</param>
        /// <returns>クライアントID</returns>
        private string ValidateClient(Input input)
        {
            if (!string.IsNullOrWhiteSpace(input.BasicClientId))
            {
                var client = Helper.CertClient(_dbContext, input.BasicClientId);
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
        /// トークン種別に応じて失効処理を振り分けます。
        /// </summary>
        /// <param name="tokenType">トークン種別</param>
        /// <param name="token">トークン値</param>
        /// <param name="clientId">クライアントID</param>
        private async Task RevokeTokenAsync(string tokenType, string token, string clientId)
        {
            if (string.Equals(tokenType, Input.TokenTypeAccessToken, StringComparison.Ordinal))
            {
                await RevokeAccessTokenAsync(token, clientId);
                return;
            }

            if (string.Equals(tokenType, Input.TokenTypeRefreshToken, StringComparison.Ordinal))
            {
                await RevokeRefreshTokenAsync(token, clientId);
                return;
            }

            throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorDescription);
        }

        /// <summary>
        /// アクセストークンを失効します。
        /// </summary>
        /// <param name="token">アクセストークン</param>
        /// <param name="clientId">クライアントID</param>
        private async Task RevokeAccessTokenAsync(string token, string clientId)
        {
            var session = new AccessTokenSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, token);
            if (string.IsNullOrWhiteSpace(raw) || !session.SetValue(raw))
            {
                return;
            }

            if (!string.Equals(session.ClientId, clientId, StringComparison.Ordinal))
            {
                return;
            }

            await _redis.DeleteAsync(AccessTokenSession.GetRedisKey(token), Code.RedisDbNo.ACCESS_TOKEN);
        }

        /// <summary>
        /// リフレッシュトークンを失効します。
        /// </summary>
        /// <param name="token">リフレッシュトークン</param>
        /// <param name="clientId">クライアントID</param>
        private async Task RevokeRefreshTokenAsync(string token, string clientId)
        {
            var session = new RefreshTokenSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, token);
            if (string.IsNullOrWhiteSpace(raw) || !session.SetValue(raw))
            {
                return;
            }

            if (!string.Equals(session.ClientId, clientId, StringComparison.Ordinal))
            {
                return;
            }

            await _redis.DeleteAsync(RefreshTokenSession.GetRedisKey(token), Code.RedisDbNo.REFRESH_TOKEN);
        }

        /// <summary>
        /// /revoke 入力を表します。
        /// </summary>
        public sealed class Input
        {
            public const string TokenTypeAccessToken = "access_token";
            public const string TokenTypeRefreshToken = "refresh_token";

            public string Token { get; set; } = string.Empty;

            public string TokenType { get; set; } = string.Empty;

            public string ClientId { get; set; } = string.Empty;

            public string? BasicClientId { get; set; }

            public string? BasicClientSecret { get; set; }

            /// <summary>
            /// HTTP リクエストから失効入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>失効入力</returns>
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
                        decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                    }
                    catch
                    {
                        throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
                    }

                    string[] parts = decoded.Split(':', 2);
                    if (parts.Length != 2)
                    {
                        throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
                    }

                    basicClientId = parts[0];
                    basicClientSecret = parts[1];
                }

                string tokenType = form["token_type"].ToString();
                if (string.IsNullOrWhiteSpace(tokenType))
                {
                    tokenType = form["token_type_hint"].ToString();
                }

                return new Input
                {
                    Token = form["token"].ToString(),
                    TokenType = tokenType,
                    ClientId = form["client_id"].ToString(),
                    BasicClientId = basicClientId,
                    BasicClientSecret = basicClientSecret
                };
            }

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(Token, "token");
                ValidateUtil.FormatParam(Token, "token", @"^[A-Za-z0-9._~-]{20,}$");

                ValidateUtil.IndispensableParam(TokenType, "token_type");
                ValidateUtil.FormatParam(TokenType, "token_type", @"^(access_token|refresh_token)$");

                if (string.IsNullOrWhiteSpace(BasicClientId))
                {
                    ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                    ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
                }
                else
                {
                    ValidateUtil.FormatParam(BasicClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
                }
            }
        }

        private sealed class ErrorOutput
        {
            public string response_code { get; }
            public string message { get; }
            public string error { get; }
            public string error_code { get; }
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
                error_code = ex.InternalCode;
                error_description = ex.ErrorDescription;
            }

            /// <summary>
            /// API 例外を OAuth エラーコードへ変換します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            /// <returns>OAuth エラーコード</returns>
            private static string ToOAuthError(ApiException ex)
            {
                if (string.Equals(ex.InternalCode, Code.ILLEGAL_CLIENT.Code, StringComparison.Ordinal))
                {
                    return "invalid_client";
                }

                if (string.Equals(ex.InternalCode, Code.REQUEST_PARAMETER_ERROR.Code, StringComparison.Ordinal))
                {
                    return "invalid_request";
                }

                if (string.Equals(ex.InternalCode, Code.INTERNAL_SERVER_ERROR.Code, StringComparison.Ordinal))
                {
                    return "server_error";
                }

                return "invalid_request";
            }
        }
    }
}
