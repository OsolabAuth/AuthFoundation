using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("authorize")]
    public class AuthorizeController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        public AuthorizeController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        [HttpGet]
        public async Task<IActionResult> GetAuthorize()
        {
            try
            {
                Input input = Input.Create(Request.HttpContext);
                input.Validate();

                Helper.CertClient(_dbContext, input.ClientId);
                if (!Helper.IsRedirectUriFormatValid(input.RedirectUri))
                {
                    throw new ApiException(Code.ILLEGAL_REDIRECT_URI, Code.ILLEGAL_REDIRECT_URI.ErrorMessage);
                }

                string? cookieSessionId = Request.Cookies[Code.AUTH_SESSION_COOKIE_KEY]
                    ?? Request.Cookies["session_id"];

                AuthSession? loginSession = await Helper.TryGetLoginSessionAsync(_redis, cookieSessionId);
                bool hasConsent = loginSession != null
                    && await HasRequiredConsentAsync(loginSession.OsolabId, input.ClientId, input.Scope);

                if (loginSession != null && hasConsent)
                {
                    AuthCodeSession codeSession = CreateAuthCodeSession(input, loginSession.OsolabId, loginSession.Email);
                    await codeSession.CreateSession(_redis);

                    string redirectUri = Helper.BuildRedirectUri(input.RedirectUri, new Dictionary<string, string>
                    {
                        ["code"] = codeSession.Code,
                        ["state"] = input.State
                    });

                    return Redirect(redirectUri);
                }

                string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
                AuthorizationSession authzSession = new AuthorizationSession
                {
                    SessionId = authzSessionId,
                    ResponseType = input.ResponseType,
                    ClientId = input.ClientId,
                    RedirectUri = input.RedirectUri,
                    State = input.State,
                    Scope = input.Scope,
                    CodeChallengeMethod = input.CodeChallengeMethod,
                    CodeChallenge = input.CodeChallenge,
                    Nonce = input.Nonce,
                    OsolabId = loginSession?.OsolabId ?? string.Empty
                };
                await authzSession.CreateSession(_redis);

                if (loginSession == null)
                {
                    return Redirect($"/login?session_id={Uri.EscapeDataString(authzSessionId)}");
                }

                return Redirect($"/terms/view?session_id={Uri.EscapeDataString(authzSessionId)}");
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new { response_code = ex.Code, message = ex.ErrorMessage })
                {
                    StatusCode = (int)ex.Status
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new { response_code = apiEx.Code, message = apiEx.ErrorMessage })
                {
                    StatusCode = (int)apiEx.Status
                };
            }
        }

        private static AuthCodeSession CreateAuthCodeSession(Input input, string osolabId, string email)
        {
            return new AuthCodeSession
            {
                Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
                OsolabId = osolabId,
                Email = email,
                ClientId = input.ClientId,
                RedirectUri = input.RedirectUri,
                Scope = input.Scope,
                CodeChallenge = input.CodeChallenge,
                CodeChallengeMethod = input.CodeChallengeMethod,
                Nonce = input.Nonce,
                State = input.State
            };
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

        public sealed class Input
        {
            public string ResponseType { get; set; } = string.Empty;
            public string ClientId { get; set; } = string.Empty;
            public string RedirectUri { get; set; } = string.Empty;
            public string State { get; set; } = string.Empty;
            public string Scope { get; set; } = string.Empty;
            public string CodeChallengeMethod { get; set; } = string.Empty;
            public string CodeChallenge { get; set; } = string.Empty;
            public string Nonce { get; set; } = string.Empty;

            public static Input Create(HttpContext context)
            {
                HttpRequest request = context.Request;
                return new Input
                {
                    ResponseType = request.Query["response_type"].ToString(),
                    ClientId = request.Query["client_id"].ToString(),
                    RedirectUri = request.Query["redirect_uri"].ToString(),
                    State = request.Query["state"].ToString(),
                    Scope = request.Query["scope"].ToString(),
                    CodeChallengeMethod = request.Query["code_challenge_method"].ToString(),
                    CodeChallenge = request.Query["code_challenge"].ToString(),
                    Nonce = request.Query["nonce"].ToString()
                };
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(ResponseType, Code.HttpQueries.RESPONSE_TYPE.Key);
                ValidateUtil.FormatParam(ResponseType, Code.HttpQueries.RESPONSE_TYPE.Key, Code.HttpQueries.RESPONSE_TYPE.Regex);
                ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
                ValidateUtil.IndispensableParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key);
                ValidateUtil.FormatParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key, Code.HttpQueries.REDIRECT_URI.Regex);
                ValidateUtil.IndispensableParam(State, Code.HttpQueries.STATE.Key);
                ValidateUtil.FormatParam(State, Code.HttpQueries.STATE.Key, Code.HttpQueries.STATE.Regex);
                ValidateUtil.IndispensableParam(Scope, Code.HttpQueries.SCOPE.Key);
                ValidateUtil.FormatParam(Scope, Code.HttpQueries.SCOPE.Key, Code.HttpQueries.SCOPE.Regex);
                ValidateUtil.IndispensableParam(CodeChallengeMethod, Code.HttpQueries.CODE_CHALLENGE_METHOD.Key);
                ValidateUtil.FormatParam(CodeChallengeMethod, Code.HttpQueries.CODE_CHALLENGE_METHOD.Key, Code.HttpQueries.CODE_CHALLENGE_METHOD.Regex);
                ValidateUtil.IndispensableParam(CodeChallenge, Code.HttpQueries.CODE_CHALLENGE.Key);
                ValidateUtil.FormatParam(CodeChallenge, Code.HttpQueries.CODE_CHALLENGE.Key, Code.HttpQueries.CODE_CHALLENGE.Regex);
                ValidateUtil.IndispensableParam(Nonce, Code.HttpQueries.NONCE.Key);
                ValidateUtil.FormatParam(Nonce, Code.HttpQueries.NONCE.Key, Code.HttpQueries.NONCE.Regex);
            }
        }
    }
}
