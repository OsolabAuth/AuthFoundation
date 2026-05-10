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
    /// <summary>     /// TokenController class.     /// </summary>
    public class TokenController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        /// <summary>         /// Initializes a new instance of TokenController.         /// </summary>
        public TokenController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        [HttpPost(Name = "PostAuthToken")]
        /// <summary>         /// Executes PostToken.         /// </summary>
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

        /// <summary>         /// Executes IsPkceValid.         /// </summary>
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

        /// <summary>         /// Executes GenerateIdToken.         /// </summary>
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

        /// <summary>         /// Executes Base64UrlEncode.         /// </summary>
        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        /// <summary>         /// Executes IsSameValue.         /// </summary>
        private static bool IsSameValue(string expected, string actual)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actual);
            return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        /// <summary>         /// Input class.         /// </summary>
        public class Input
        {
            /// <summary>             /// Gets or sets FlowType.             /// </summary>
            public string FlowType { get; set; } = string.Empty;
            /// <summary>             /// Gets or sets Body.             /// </summary>
            public JsonBody Body { get; set; } = new();

            /// <summary>             /// JsonBody class.             /// </summary>
            public class JsonBody
            {
                [JsonProperty("grant_type")]
                /// <summary>                 /// Gets or sets GrantType.                 /// </summary>
                public string GrantType { get; set; } = string.Empty;

                [JsonProperty("client_id")]
                /// <summary>                 /// Gets or sets ClientId.                 /// </summary>
                public string ClientId { get; set; } = string.Empty;

                [JsonProperty("client_secret")]
                /// <summary>                 /// Gets or sets ClientSecret.                 /// </summary>
                public string ClientSecret { get; set; } = string.Empty;

                [JsonProperty("code_verifier")]
                /// <summary>                 /// Gets or sets CodeVerifier.                 /// </summary>
                public string CodeVerifier { get; set; } = string.Empty;

                [JsonProperty("code")]
                /// <summary>                 /// Gets or sets Code.                 /// </summary>
                public string Code { get; set; } = string.Empty;
            }

            /// <summary>             /// Initializes a new instance of Input.             /// </summary>
            private Input() { }

            /// <summary>             /// Executes CreateAsync.             /// </summary>
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

            /// <summary>             /// Executes ValidationCheck.             /// </summary>
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

        /// <summary>         /// Output class.         /// </summary>
        private class Output
        {
            /// <summary>             /// Gets or sets StatusCode.             /// </summary>
            public string StatusCode { get; }
            /// <summary>             /// Gets or sets Message.             /// </summary>
            public string Message { get; }
            /// <summary>             /// Gets or sets AccessToken.             /// </summary>
            public string? AccessToken { get; }
            /// <summary>             /// Gets or sets IdToken.             /// </summary>
            public string? IdToken { get; }
            /// <summary>             /// Gets or sets TokenType.             /// </summary>
            public string? TokenType { get; }
            /// <summary>             /// Gets or sets ExpiresIn.             /// </summary>
            public int? ExpiresIn { get; }

            /// <summary>             /// Initializes a new instance of Output.             /// </summary>
            public Output(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            /// <summary>             /// Initializes a new instance of Output.             /// </summary>
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
