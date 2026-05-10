using System.IO;
using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("login")]
    /// <summary>     /// LoginController class.     /// </summary>
    public class LoginController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;

        /// <summary>         /// Initializes a new instance of LoginController.         /// </summary>
        public LoginController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
        }

        [HttpGet("view", Name = "GetLoginView")]
        /// <summary>         /// Executes GetLoginView.         /// </summary>
        public IActionResult GetLoginView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("login.html").Replace("__SESSION_ID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        /// <summary>         /// Executes LoadTemplate.         /// </summary>
        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Auth", fileName);
            return System.IO.File.ReadAllText(path);
        }

        [HttpPost(Name = "PostLogin")]
        /// <summary>         /// Executes PostLogin.         /// </summary>
        public async Task<IActionResult> PostLogin()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.ValidationCheck();

                AuthorizationSession authzSession = await GetAuthorizationSessionAsync(input.SessionId);

                osolab_user? user = _dbContext.osolab_users.SingleOrDefault(x =>
                    x.email == input.Body.Email &&
                    x.status == Code.Status.ACTIVE);
                if (user == null)
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                string inputPassHash = Helper.GetPassHash(input.Body.Password, user.nonce);
                if (!IsSameHash(user.password, inputPassHash))
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                string loginSessionId = Helper.GenerateRandomCode(Code.Session.LENGTH, Code.Session.CHARACTORS);
                AuthSession loginSession = new AuthSession(loginSessionId, user.osolab_id, user.email, authzSession.ClientId);
                await loginSession.CreateSession(_redis);
                authzSession.OsolabId = user.osolab_id;
                await authzSession.CreateSession(_redis);

                Response.Cookies.Append("session_id", loginSessionId, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Lax,
                    MaxAge = TimeSpan.FromSeconds(AppConfig.SessionExpireSec)
                });

                bool hasConsent = await HasRequiredConsentAsync(user.osolab_id, authzSession.ClientId, authzSession.Scope);
                if (hasConsent)
                {
                    AuthCodeSession codeSession = await CreateAuthCodeFromAuthorizationSessionAsync(authzSession);
                    string redirectUrl = BuildRedirectUri(authzSession.RedirectUri, codeSession.Code, authzSession.State);
                    return Ok(Output.ForRedirect(redirectUrl));
                }

                string nextUrl = $"/term/view?session_id={Uri.EscapeDataString(input.SessionId)}";
                return Ok(Output.ForNextAction("term", input.SessionId, nextUrl));
            }
            catch (ApiException aex)
            {
                return new ObjectResult(Output.ForError(aex)) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(Output.ForError(aex)) { StatusCode = (int)aex.Status };
            }
        }

        /// <summary>         /// Executes GetAuthorizationSessionAsync.         /// </summary>
        private async Task<AuthorizationSession> GetAuthorizationSessionAsync(string sessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(sessionId));
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is not found");
            }

            AuthorizationSession? authzSession = JsonConvert.DeserializeObject<AuthorizationSession>(raw);
            if (authzSession == null)
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
            }

            return authzSession;
        }

        /// <summary>         /// Executes IsSameHash.         /// </summary>
        private static bool IsSameHash(string expectedHash, string actualHash)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expectedHash);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actualHash);
            return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        /// <summary>         /// Executes CreateAuthCodeFromAuthorizationSessionAsync.         /// </summary>
        private async Task<AuthCodeSession> CreateAuthCodeFromAuthorizationSessionAsync(AuthorizationSession authzSession)
        {
            osolab_user? user = await _dbContext.osolab_users
                .SingleOrDefaultAsync(x => x.osolab_id == authzSession.OsolabId && x.status == Code.Status.ACTIVE);
            if (user == null)
            {
                throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
            }

            AuthCodeSession codeSession = new AuthCodeSession
            {
                Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
                OsolabId = authzSession.OsolabId,
                Email = user.email,
                ClientId = authzSession.ClientId,
                RedirectUri = authzSession.RedirectUri,
                Scope = authzSession.Scope,
                CodeChallenge = authzSession.CodeChallenge,
                CodeChallengeMethod = authzSession.CodeChallengeMethod,
                Nonce = authzSession.Nonce,
                State = authzSession.State
            };

            await codeSession.CreateSession(_redis);
            return codeSession;
        }

        /// <summary>         /// Executes HasRequiredConsentAsync.         /// </summary>
        private async Task<bool> HasRequiredConsentAsync(string osolabId, string clientId, string requestedScope)
        {
            string[] requestedScopes = requestedScope
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            client_term[] requiredTerms = await _dbContext.client_terms
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .ToArrayAsync();

            client_scope[] requiredScopes = await _dbContext.client_scopes
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .ToArrayAsync();

            List<user_term> agreedTermRows = await _dbContext.user_terms
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .ToListAsync();

            bool hasAllRequiredTerms = requiredTerms.All(rt =>
                agreedTermRows.Any(ut => ut.term_id == rt.term_id && ut.term_version == rt.term_version));
            if (!hasAllRequiredTerms)
            {
                return false;
            }

            HashSet<string> requiredScopeSet = requiredScopes.Select(x => x.scope).ToHashSet(StringComparer.Ordinal);
            if (!requiredScopeSet.IsSubsetOf(requestedScopes))
            {
                return false;
            }

            HashSet<string> agreedScopes = await _dbContext.user_client_scopes
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .Select(x => x.scope)
                .ToHashSetAsync();

            return requiredScopeSet.All(agreedScopes.Contains) && requestedScopes.All(agreedScopes.Contains);
        }

        /// <summary>         /// Executes BuildRedirectUri.         /// </summary>
        private static string BuildRedirectUri(string redirectUri, string code, string state)
        {
            string separator = redirectUri.Contains('?') ? "&" : "?";
            return $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        }

        /// <summary>         /// Input class.         /// </summary>
        public class Input
        {
            /// <summary>             /// Gets or sets SessionId.             /// </summary>
            public string SessionId { get; set; } = string.Empty;
            /// <summary>             /// Gets or sets Body.             /// </summary>
            public JsonBody Body { get; set; } = new();

            /// <summary>             /// JsonBody class.             /// </summary>
            public class JsonBody
            {
                [JsonProperty("email")]
                /// <summary>                 /// Gets or sets Email.                 /// </summary>
                public string Email { get; set; } = string.Empty;

                [JsonProperty("password")]
                /// <summary>                 /// Gets or sets Password.                 /// </summary>
                public string Password { get; set; } = string.Empty;
            }

            /// <summary>             /// Executes CreateAsync.             /// </summary>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeApplicationJson(request.ContentType);

                using var reader = new StreamReader(request.Body, Encoding.UTF8);
                string rawJson = await reader.ReadToEndAsync();
                JsonBody? body = JsonConvert.DeserializeObject<JsonBody>(rawJson);
                if (body == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "invalid json object");
                }

                return new Input
                {
                    SessionId = request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString(),
                    Body = body
                };
            }

            /// <summary>             /// Executes ValidationCheck.             /// </summary>
            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(Body.Email, Code.HttpBodies.EMAIL.Key);
                ValidateUtil.FormatParam(Body.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
                ValidateUtil.IndispensableParam(Body.Password, Code.HttpBodies.PASSWORD.Key);
                ValidateUtil.FormatParam(Body.Password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            }
        }

        /// <summary>         /// Output class.         /// </summary>
        private class Output
        {
            /// <summary>             /// Gets or sets StatusCode.             /// </summary>
            public string StatusCode { get; set; } = Code.SUCCESS.Code;
            /// <summary>             /// Gets or sets Message.             /// </summary>
            public string Message { get; set; } = Code.SUCCESS.ErrorMessage;
            /// <summary>             /// Gets or sets NextAction.             /// </summary>
            public string? NextAction { get; set; }
            /// <summary>             /// Gets or sets AuthSessionId.             /// </summary>
            public string? AuthSessionId { get; set; }
            /// <summary>             /// Gets or sets NextUrl.             /// </summary>
            public string? NextUrl { get; set; }
            /// <summary>             /// Gets or sets RedirectUrl.             /// </summary>
            public string? RedirectUrl { get; set; }

            /// <summary>             /// Executes ForNextAction.             /// </summary>
            public static Output ForNextAction(string nextAction, string authSessionId, string nextUrl)
            {
                return new Output { NextAction = nextAction, AuthSessionId = authSessionId, NextUrl = nextUrl };
            }

            /// <summary>             /// Executes ForRedirect.             /// </summary>
            public static Output ForRedirect(string redirectUrl)
            {
                return new Output { RedirectUrl = redirectUrl };
            }

            /// <summary>             /// Executes ForError.             /// </summary>
            public static Output ForError(ApiException ex)
            {
                return new Output { StatusCode = ex.Code, Message = ex.ErrorMessage };
            }
        }
    }
}
