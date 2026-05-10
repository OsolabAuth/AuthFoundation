using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("token")]
    [Route("api/auth/token")]
    public class TokenController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly OidcSigningService _oidcSigningService;

        public TokenController(OsolabAuthContext dbContext, IRedisClient redis, OidcSigningService oidcSigningService)
        {
            _dbContext = dbContext;
            _redis = redis;
            _oidcSigningService = oidcSigningService;
        }

        [HttpPost]
        public async Task<IActionResult> PostToken()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                string clientId = ValidateClient(input);

                string? raw = await _redis.GetStringAsync(AuthCodeSession.GetRedisKey(input.AuthorizationCode));
                if (string.IsNullOrWhiteSpace(raw))
                {
                    throw new ApiException(Code.INVALID_AUTH_CODE, Code.INVALID_AUTH_CODE.ErrorMessage);
                }

                AuthCodeSession? codeSession = JsonConvert.DeserializeObject<AuthCodeSession>(raw);
                if (codeSession == null)
                {
                    throw new ApiException(Code.INVALID_AUTH_CODE, Code.INVALID_AUTH_CODE.ErrorMessage);
                }

                if (!string.Equals(codeSession.ClientId, clientId, StringComparison.Ordinal))
                {
                    throw new ApiException(Code.INVALID_AUTH_CODE, Code.INVALID_AUTH_CODE.ErrorMessage);
                }

                if (!string.Equals(codeSession.RedirectUri, input.RedirectUri, StringComparison.Ordinal))
                {
                    throw new ApiException(Code.ILLEGAL_REDIRECT_URI, Code.ILLEGAL_REDIRECT_URI.ErrorMessage);
                }

                if (!IsPkceValid(input.CodeVerifier, codeSession.CodeChallenge, codeSession.CodeChallengeMethod))
                {
                    throw new ApiException(Code.INVALID_AUTH_CODE, Code.INVALID_AUTH_CODE.ErrorMessage);
                }

                string tokenId = Helper.GenerateHex(32).ToLowerInvariant();
                string accessToken = $"{codeSession.OsolabId}_{tokenId}_{clientId}";
                string refreshToken = $"{codeSession.OsolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";

                AccessTokenSession accessTokenSession = new AccessTokenSession
                {
                    AccessToken = accessToken,
                    OsolabId = codeSession.OsolabId,
                    ClientId = clientId,
                    Scope = codeSession.Scope
                };
                await accessTokenSession.CreateSession(_redis);

                RefreshTokenSession refreshTokenSession = new RefreshTokenSession
                {
                    RefreshToken = refreshToken,
                    OsolabId = codeSession.OsolabId,
                    ClientId = clientId,
                    Scope = codeSession.Scope
                };
                await refreshTokenSession.CreateSession(_redis);

                string idToken = _oidcSigningService.CreateIdToken(codeSession, Helper.ParseScopes(codeSession.Scope));

                await _redis.DeleteAsync(AuthCodeSession.GetRedisKey(input.AuthorizationCode));

                return Ok(new
                {
                    response_code = Code.SUCCESS.Code,
                    access_token = accessToken,
                    refresh_token = refreshToken,
                    token_type = Code.AccessToken.TOKEN_TYPE_BEARER,
                    expires_in = AppConfig.AccessTokenExpireSec,
                    refresh_token_expires_in = AppConfig.RefreshTokenExpireSec,
                    scope = codeSession.Scope,
                    id_token = idToken
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.Status
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.Status
                };
            }
        }

        private string ValidateClient(Input input)
        {
            if (!string.IsNullOrWhiteSpace(input.BasicClientId))
            {
                if (!string.IsNullOrWhiteSpace(input.ClientId) && !string.Equals(input.ClientId, input.BasicClientId, StringComparison.Ordinal))
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);
                }

                client_master client = Helper.CertClient(_dbContext, input.BasicClientId);
                if (!FixedTimeEquals(client.client_secret, input.BasicClientSecret ?? string.Empty))
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);
                }

                return input.BasicClientId;
            }

            if (string.IsNullOrWhiteSpace(input.ClientId))
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);
            }

            Helper.CertClient(_dbContext, input.ClientId);
            return input.ClientId;
        }

        private static bool IsPkceValid(string verifier, string challenge, string method)
        {
            if (!string.Equals(method, "S256", StringComparison.Ordinal))
            {
                return false;
            }

            byte[] bytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
            string calculated = Base64UrlEncode(bytes);
            return FixedTimeEquals(calculated, challenge);
        }

        private static bool FixedTimeEquals(string expected, string actual)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actual);
            return expectedBytes.Length == actualBytes.Length
                && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public sealed class Input
        {
            public string FlowType { get; set; } = string.Empty;
            public string GrantType { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public string AuthorizationCode { get; set; } = string.Empty;
            public string CodeVerifier { get; set; } = string.Empty;
            public string RedirectUri { get; set; } = string.Empty;
            public string? BasicClientId { get; set; }
            public string? BasicClientSecret { get; set; }

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
                    string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                    string[] parts = decoded.Split(':', 2);
                    if (parts.Length == 2)
                    {
                        basicClientId = parts[0];
                        basicClientSecret = parts[1];
                    }
                }

                return new Input
                {
                    FlowType = request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key].ToString(),
                    GrantType = form["grant_type"].ToString(),
                    ClientId = form["client_id"].ToString(),
                    AuthorizationCode = form["code"].ToString(),
                    CodeVerifier = form["code_verifier"].ToString(),
                    RedirectUri = form["redirect_uri"].ToString(),
                    BasicClientId = basicClientId,
                    BasicClientSecret = basicClientSecret
                };
            }

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

                ValidateUtil.IndispensableParam(AuthorizationCode, Code.HttpBodies.AUTH_CODE.Key);
                ValidateUtil.FormatParam(AuthorizationCode, Code.HttpBodies.AUTH_CODE.Key, Code.HttpBodies.AUTH_CODE.Regex);
                ValidateUtil.IndispensableParam(CodeVerifier, Code.HttpBodies.CODE_VERIFIER.Key);
                ValidateUtil.FormatParam(CodeVerifier, Code.HttpBodies.CODE_VERIFIER.Key, Code.HttpBodies.CODE_VERIFIER.Regex);
                ValidateUtil.IndispensableParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key);
                ValidateUtil.FormatParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key, Code.HttpQueries.REDIRECT_URI.Regex);
            }
        }

        private sealed class ErrorOutput
        {
            public string response_code { get; }
            public string message { get; }

            public ErrorOutput(ApiException ex)
            {
                response_code = ex.Code;
                message = ex.ErrorMessage;
            }
        }
    }
}
