using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
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
    public class LoginController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;

        public LoginController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
        }

        [HttpGet]
        [HttpGet("view")]
        public IActionResult GetLogin()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("login.html").Replace("__SESSION_ID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        [HttpPost]
        public async Task<IActionResult> PostLogin()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                osolab_user? user = _dbContext.osolab_users.SingleOrDefault(x =>
                    x.email == input.Email && x.status == Code.Status.ACTIVE);
                if (user == null)
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                string passwordHashHex = NormalizePasswordHash(input.Password);
                string inputPassHash = Helper.GetPassHash(passwordHashHex, user.nonce);
                if (!IsSameValue(user.password, inputPassHash))
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                string loginSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
                AuthSession loginSession = new AuthSession(loginSessionId, user.osolab_id, user.email, string.Empty);
                await loginSession.CreateSession(_redis);
                SetAuthCookie(loginSessionId);

                if (string.IsNullOrWhiteSpace(input.SessionId))
                {
                    return Ok(new Output
                    {
                        result = "logged_in",
                        response_code = "00006",
                        message = "Logged in, but authorization session is missing or expired."
                    });
                }

                AuthorizationSession? authzSession = await GetAuthorizationSessionIfExistsAsync(input.SessionId);
                if (authzSession == null)
                {
                    return Ok(new Output
                    {
                        result = "logged_in",
                        response_code = "00006",
                        message = "Logged in, but authorization session is missing or expired."
                    });
                }

                authzSession.OsolabId = user.osolab_id;
                await authzSession.CreateSession(_redis);

                bool hasConsent = await HasRequiredConsentAsync(user.osolab_id, authzSession.ClientId, authzSession.Scope);
                if (hasConsent)
                {
                    AuthCodeSession codeSession = await CreateAuthCodeFromAuthorizationSessionAsync(authzSession, user.email);
                    string location = Helper.BuildRedirectUri(authzSession.RedirectUri, new Dictionary<string, string>
                    {
                        ["code"] = codeSession.Code,
                        ["state"] = authzSession.State
                    });

                    Response.Headers.Location = location;
                    return Ok(new Output { result = "redirect", response_code = Code.SUCCESS.Code, message = Code.SUCCESS.ErrorMessage });
                }

                string termLocation = $"/terms/view?session_id={Uri.EscapeDataString(input.SessionId)}";
                Response.Headers.Location = termLocation;
                return Ok(new Output { result = "redirect", response_code = Code.SUCCESS.Code, message = Code.SUCCESS.ErrorMessage });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new Output(ex)) { StatusCode = (int)ex.Status };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new Output(apiEx)) { StatusCode = (int)apiEx.Status };
            }
        }

        private void SetAuthCookie(string sessionId)
        {
            CookieOptions options = new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Lax,
                MaxAge = TimeSpan.FromSeconds(AppConfig.SessionExpireSec)
            };

            Response.Cookies.Append(Code.AUTH_SESSION_COOKIE_KEY, sessionId, options);
            Response.Cookies.Append("session_id", sessionId, options);
        }

        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Auth", fileName);
            return System.IO.File.ReadAllText(path);
        }

        private async Task<AuthorizationSession?> GetAuthorizationSessionIfExistsAsync(string sessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(sessionId));
            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            return JsonConvert.DeserializeObject<AuthorizationSession>(raw);
        }

        private async Task<AuthCodeSession> CreateAuthCodeFromAuthorizationSessionAsync(AuthorizationSession authzSession, string email)
        {
            AuthCodeSession codeSession = new AuthCodeSession
            {
                Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
                OsolabId = authzSession.OsolabId,
                Email = email,
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

        private async Task<bool> HasRequiredConsentAsync(string osolabId, string clientId, string requestedScope)
        {
            string[] requestedScopes = Helper.ParseScopes(requestedScope);

            List<client_term> requiredTerms = await _dbContext.client_terms
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .ToListAsync();

            List<user_term> agreedTermRows = await _dbContext.user_terms
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .ToListAsync();

            bool hasAllRequiredTerms = requiredTerms.All(rt =>
                agreedTermRows.Any(ut => ut.term_id == rt.term_id && ut.term_version == rt.term_version));
            if (!hasAllRequiredTerms)
            {
                return false;
            }

            HashSet<string> requiredScopeSet = await _dbContext.client_scopes
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .Select(x => x.scope)
                .ToHashSetAsync(StringComparer.Ordinal);

            if (!requiredScopeSet.IsSubsetOf(requestedScopes))
            {
                return false;
            }

            HashSet<string> agreedScopes = await _dbContext.user_client_scopes
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .Select(x => x.scope)
                .ToHashSetAsync(StringComparer.Ordinal);

            return requiredScopeSet.All(agreedScopes.Contains) && requestedScopes.All(agreedScopes.Contains);
        }

        private static string NormalizePasswordHash(string passwordInput)
        {
            if (Regex.IsMatch(passwordInput, Code.HttpBodies.PASSWORD.Regex))
            {
                return passwordInput.ToUpperInvariant();
            }

            byte[] plainBytes = Encoding.UTF8.GetBytes(passwordInput);
            byte[] sha = SHA256.HashData(plainBytes);
            return Convert.ToHexString(sha);
        }

        private static bool IsSameValue(string expected, string actual)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actual);
            return expectedBytes.Length == actualBytes.Length
                && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        public sealed class Input
        {
            public string SessionId { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);

                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    SessionId = request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString(),
                    Email = form["email"].ToString(),
                    Password = form["password"].ToString()
                };
            }

            public void Validate()
            {
                if (!string.IsNullOrWhiteSpace(SessionId))
                {
                    ValidateUtil.FormatParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);
                }

                ValidateUtil.IndispensableParam(Email, Code.HttpBodies.EMAIL.Key);
                ValidateUtil.FormatParam(Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
                ValidateUtil.IndispensableParam(Password, Code.HttpBodies.PASSWORD.Key);
                if (!Regex.IsMatch(Password, Code.HttpBodies.PASSWORD.Regex))
                {
                    ValidateUtil.FormatParam(Password, Code.HttpBodies.PASSWORD.Key, @"^.{1,256}$");
                }
            }
        }

        private sealed class Output
        {
            public string? result { get; set; }
            public string? response_code { get; set; }
            public string? message { get; set; }

            public Output() { }

            public Output(ApiException ex)
            {
                result = "error";
                response_code = ex.Code;
                message = ex.ErrorMessage;
            }
        }
    }
}
