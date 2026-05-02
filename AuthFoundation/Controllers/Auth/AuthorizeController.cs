using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("Authorize")]
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
                input.ValidationCheck();

                client_master client = Helper.CertClient(_dbContext, input.ClientId);

                AuthSession? loginSession = await Helper.TryGetLoginSessionAsync(Request.Cookies["session_id"]);
                bool hasConsent = loginSession != null && await HasRequiredConsentAsync(loginSession.OsolabId, input.ClientId, input.Scope);

                if (loginSession != null && hasConsent)
                {
                    AuthCodeSession codeSession = CreateAuthCodeSession(input, loginSession.OsolabId, loginSession.Email);
                    await codeSession.CreateSession(_redis);
                    string redirectUri = BuildRedirectUri(input.RedirectUri, codeSession.Code, input.State);
                    return Redirect(redirectUri);
                }

                string authzSessionId = Helper.GenerateRandomCode(Code.Session.LENGTH, Code.Session.CHARACTORS);
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
                    return Redirect($"/login/view?session_id={Uri.EscapeDataString(authzSessionId)}");
                }

                return Redirect($"/term/view?session_id={Uri.EscapeDataString(authzSessionId)}");
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

        private static AuthCodeSession CreateAuthCodeSession(Input input, string osolabId, string email)
        {
            string code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS);
            return new AuthCodeSession
            {
                Code = code,
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

            bool hasAllRequiredTerms = await _dbContext.user_terms
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .Select(x => new { x.term_id, x.term_version })
                .ToListAsync()
                .ContinueWith(t =>
                {
                    var agreed = t.Result.ToHashSet();
                    return requiredTerms.All(rt => agreed.Contains(new { term_id = rt.term_id, term_version = rt.term_version }));
                });

            if (!hasAllRequiredTerms)
            {
                return false;
            }

            if (requestedScopes.Length == 0)
            {
                return true;
            }

            var requiredScopeSet = requiredScopes.Select(x => x.scope).ToHashSet(StringComparer.Ordinal);
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

        private static string BuildRedirectUri(string redirectUri, string code, string state)
        {
            string separator = redirectUri.Contains('?') ? "&" : "?";
            return $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        }

        public class Input
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

            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(ResponseType, Code.HttpQueries.RESPONSE_TYPE.Key);
                ValidateUtil.FormatParam(ResponseType, Code.HttpQueries.RESPONSE_TYPE.Key, Code.HttpQueries.RESPONSE_TYPE.Regex);
                ValidateUtil.IndispensableParam(ClientId, "client_id");
                ValidateUtil.FormatParam(ClientId, "client_id", Code.HttpHeaders.X_AUTH_CLIENT_ID.Regex);
                ValidateUtil.IndispensableParam(RedirectUri, "redirect_uri");
                ValidateUtil.IndispensableParam(State, "state");
                ValidateUtil.IndispensableParam(Scope, "scope");
                ValidateUtil.IndispensableParam(Nonce, "nonce");
                ValidateUtil.IndispensableParam(CodeChallengeMethod, Code.HttpQueries.CODE_CHALLENGE_METHOD.Key);
                ValidateUtil.FormatParam(CodeChallengeMethod, Code.HttpQueries.CODE_CHALLENGE_METHOD.Key, Code.HttpQueries.CODE_CHALLENGE_METHOD.Regex);
                ValidateUtil.IndispensableParam(CodeChallenge, Code.HttpQueries.CODE_CHALLENGE.Key);
                ValidateUtil.FormatParam(CodeChallenge, Code.HttpQueries.CODE_CHALLENGE.Key, Code.HttpQueries.CODE_CHALLENGE.Regex);
            }
        }

        private class Output
        {
            public string StatusCode { get; set; } = Common.Code.SUCCESS.Code;
            public string Message { get; set; } = Common.Code.SUCCESS.ErrorMessage;

            public static Output ForError(ApiException ex)
            {
                return new Output { StatusCode = ex.Code, Message = ex.ErrorMessage };
            }
        }
    }
}
