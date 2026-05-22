using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// 繝医・繧ｯ繝ｳ螟ｱ蜉ｹ繧貞・逅・＠縺ｾ縺吶・
    /// </summary>
    [ApiController]
    [Route("revoke")]
    [Route("api/auth/revoke")]
    public class RevokeController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        /// <summary>
        /// RevokeController 繧貞・譛溷喧縺励∪縺吶・
        /// </summary>
        public RevokeController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        /// <summary>
        /// 繝医・繧ｯ繝ｳ繧貞､ｱ蜉ｹ縺励∪縺吶・
        /// </summary>
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

        private static void SetNoStoreHeaders(HttpResponse response)
        {
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["Pragma"] = "no-cache";
        }

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
        /// 螟ｱ蜉ｹ蜈･蜉帙ｒ陦ｨ縺励∪縺吶・
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
            /// HTTP 繝ｪ繧ｯ繧ｨ繧ｹ繝医°繧牙・蜉帙ｒ逕滓・縺励∪縺吶・
            /// </summary>
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
            /// 蜈･蜉帛､繧呈､懆ｨｼ縺励∪縺吶・
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
            public string error_description { get; }

            public ErrorOutput(ApiException ex)
            {
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
                error = ToOAuthError(ex);
                error_description = ex.ErrorDescription;
            }

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
