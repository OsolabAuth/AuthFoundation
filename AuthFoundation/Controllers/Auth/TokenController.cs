using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("api/auth/token")]
    public class TokenController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        public TokenController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        [HttpPost(Name = "PostAuthToken")]
        public async Task<IActionResult> PostToken()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.ValidationCheck();

                client_master client = Helper.CertClient(_dbContext, input.Body.ClientId);
                if (client.status != Code.Status.ACTIVE)
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);
                }
                if (!IsSameValue(client.client_secret, input.Body.ClientSecret))
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, "client_secretが不正です");
                }

                string authCodeRedisKey = AuthCodeSession.GetRedisKey(input.Body.Code);
                string? authCodeRaw = await _redis.GetStringAsync(authCodeRedisKey);
                if (string.IsNullOrEmpty(authCodeRaw))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "認可コードが不正です");
                }

                AuthCodeSession? authCodeSession = JsonConvert.DeserializeObject<AuthCodeSession>(authCodeRaw);
                if (authCodeSession == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "認可コードが不正です");
                }
                if (authCodeSession.ClientId != input.Body.ClientId)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "認可コードが不正です");
                }
                if (!IsPkceValid(input.Body.CodeVerifier, authCodeSession.CodeChallenge, authCodeSession.CodeChallengeMethod))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "PKCE検証に失敗しました");
                }

                string accessToken = Helper.GenerateRandomCode(Code.AccessToken.LENGTH, Code.AccessToken.CHARACTORS);
                AccessTokenSession accessTokenSession = new AccessTokenSession
                {
                    AccessToken = accessToken,
                    OsolabId = authCodeSession.OsolabId,
                    ClientId = authCodeSession.ClientId,
                    Scope = authCodeSession.Scope
                };
                await accessTokenSession.CreateSession(_redis);

                string idToken = GenerateIdToken(authCodeSession);
                await _redis.DeleteAsync(authCodeRedisKey);

                return new OkObjectResult(new Output(accessToken, idToken));
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new Output(aex))
                {
                    StatusCode = (int)aex.Status
                };
            }
            catch (Exception ex)
            {
                return new ObjectResult(
                    new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                {
                    StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        private static bool IsPkceValid(string codeVerifier, string codeChallenge, string codeChallengeMethod)
        {
            if (codeChallengeMethod != "S256")
            {
                return false;
            }

            byte[] verifierBytes = Encoding.ASCII.GetBytes(codeVerifier);
            byte[] hashed = SHA256.HashData(verifierBytes);
            string calculated = Base64UrlEncode(hashed);
            return IsSameValue(calculated, codeChallenge);
        }

        private static string GenerateIdToken(AuthCodeSession authCodeSession)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset exp = now.AddSeconds(AppConfig.IdTokenExpireSec);
            string headerJson = System.Text.Json.JsonSerializer.Serialize(new { alg = "HS256", typ = "JWT" });
            string payloadJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                iss = "AuthFoundation",
                sub = authCodeSession.OsolabId,
                aud = authCodeSession.ClientId,
                iat = now.ToUnixTimeSeconds(),
                exp = exp.ToUnixTimeSeconds(),
                nonce = authCodeSession.Nonce,
                email = authCodeSession.Email
            });

            string header = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{header}.{payload}";

            byte[] key = Encoding.UTF8.GetBytes(AppConfig.PasswordHashKey);
            byte[] sig = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(signingInput));
            string signature = Base64UrlEncode(sig);
            return $"{signingInput}.{signature}";
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static bool IsSameValue(string expected, string actual)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actual);
            return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        public class Input
        {
            public string FlowType { get; set; } = string.Empty;
            public JsonBody Body { get; set; } = new();

            public class JsonBody
            {
                [JsonProperty("grant_type")]
                public string GrantType { get; set; } = string.Empty;

                [JsonProperty("client_id")]
                public string ClientId { get; set; } = string.Empty;

                [JsonProperty("client_secret")]
                public string ClientSecret { get; set; } = string.Empty;

                [JsonProperty("code_verifier")]
                public string CodeVerifier { get; set; } = string.Empty;

                [JsonProperty("code")]
                public string Code { get; set; } = string.Empty;
            }

            private Input() { }

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeApplicationJson(request.ContentType);

                using var reader = new StreamReader(request.Body, Encoding.UTF8);
                string rawJson = await reader.ReadToEndAsync();
                JsonBody? body = null;
                try
                {
                    body = JsonConvert.DeserializeObject<JsonBody>(rawJson);
                }
                catch
                {
                }

                if (body == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "JSONオブジェクトが不正です");
                }

                return new Input
                {
                    FlowType = request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key].ToString(),
                    Body = body
                };
            }

            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(FlowType, Code.HttpHeaders.X_FLOW_TYPE.Key);
                ValidateUtil.FormatParam(FlowType, Code.HttpHeaders.X_FLOW_TYPE.Key, Code.HttpHeaders.X_FLOW_TYPE.Regex);

                ValidateUtil.IndispensableParam(Body.GrantType, Code.HttpBodies.GRANT_TYPE.Key);
                ValidateUtil.FormatParam(Body.GrantType, Code.HttpBodies.GRANT_TYPE.Key, Code.HttpBodies.GRANT_TYPE.Regex);

                ValidateUtil.IndispensableParam(Body.ClientId, "client_id");
                ValidateUtil.FormatParam(Body.ClientId, "client_id", Code.HttpHeaders.X_AUTH_CLIENT_ID.Regex);

                ValidateUtil.IndispensableParam(Body.ClientSecret, "client_secret");
                ValidateUtil.IndispensableParam(Body.CodeVerifier, Code.HttpBodies.CODE_VERIFIER.Key);
                ValidateUtil.FormatParam(Body.CodeVerifier, Code.HttpBodies.CODE_VERIFIER.Key, Code.HttpBodies.CODE_VERIFIER.Regex);

                ValidateUtil.IndispensableParam(Body.Code, Code.HttpBodies.AUTH_CODE.Key);
                ValidateUtil.FormatParam(Body.Code, Code.HttpBodies.AUTH_CODE.Key, Code.HttpBodies.AUTH_CODE.Regex);
            }
        }

        private class Output
        {
            public string StatusCode { get; }
            public string Message { get; }
            public string? AccessToken { get; }
            public string? IdToken { get; }
            public string? TokenType { get; }
            public int? ExpiresIn { get; }

            public Output(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            public Output(string accessToken, string idToken)
            {
                StatusCode = Common.Code.SUCCESS.Code;
                Message = Common.Code.SUCCESS.ErrorMessage;
                AccessToken = accessToken;
                IdToken = idToken;
                TokenType = Code.AccessToken.TOKEN_TYPE_BEARER;
                ExpiresIn = AppConfig.AccessTokenExpireSec;
            }
        }
    }
}
