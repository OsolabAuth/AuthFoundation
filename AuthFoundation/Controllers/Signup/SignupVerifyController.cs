using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Signup
{
    [ApiController]
    [Route("Signup/Verify")]
    /// <summary>     /// SignupVerifyController class.     /// </summary>
    public class SignupVerifyController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        /// <summary>         /// Initializes a new instance of SignupVerifyController.         /// </summary>
        public SignupVerifyController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        [HttpGet]
        /// <summary>         /// Executes Verify.         /// </summary>
        public async Task<IActionResult> Verify()
        {
            try
            {
                string token = Request.Query["token"].ToString();
                ValidateUtil.IndispensableParam(token, "token");

                string? raw = await _redis.GetStringAsync(MailVerificationSession.GetRedisKey(token));
                if (string.IsNullOrWhiteSpace(raw))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification token is invalid");
                }

                MailVerificationSession? verify = JsonConvert.DeserializeObject<MailVerificationSession>(raw);
                if (verify == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification session is invalid");
                }

                var user = _dbContext.osolab_users.SingleOrDefault(x => x.osolab_id == verify.OsolabId && x.status == Code.Status.TENTATIVE);
                if (user == null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "tentative user is not found");
                }

                user.status = Code.Status.ACTIVE;
                user.update_datetime = DateTime.UtcNow;
                _dbContext.SaveChanges();
                await _redis.DeleteAsync(MailVerificationSession.GetRedisKey(token));

                string loginSessionId = Helper.GenerateRandomCode(Code.Session.LENGTH, Code.Session.CHARACTORS);
                AuthSession loginSession = new AuthSession(loginSessionId, user.osolab_id, user.email, string.Empty);
                await loginSession.CreateSession(_redis);
                Response.Cookies.Append("session_id", loginSessionId, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Lax,
                    MaxAge = TimeSpan.FromSeconds(AppConfig.SessionExpireSec)
                });

                AuthorizationSession authz = await GetAuthzSession(verify.SessionId);
                bool hasConsent = await HasRequiredConsentAsync(user.osolab_id, authz.ClientId, authz.Scope);
                if (hasConsent)
                {
                    return Redirect(BuildAuthorizeUrl(authz));
                }

                return Redirect($"/term/view?session_id={Uri.EscapeDataString(authz.SessionId)}");
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }

        /// <summary>         /// Executes GetAuthzSession.         /// </summary>
        private async Task<AuthorizationSession> GetAuthzSession(string authzSessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(authzSessionId));
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is not found");
            }

            AuthorizationSession? s = JsonConvert.DeserializeObject<AuthorizationSession>(raw);
            if (s == null)
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
            }

            return s;
        }

        /// <summary>         /// Executes HasRequiredConsentAsync.         /// </summary>
        private async Task<bool> HasRequiredConsentAsync(string osolabId, string clientId, string requestedScope)
        {
            string[] requestedScopes = requestedScope
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            var requiredTerms = _dbContext.client_terms
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .ToList();
            var agreedTerms = _dbContext.user_terms
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .ToList();
            if (!requiredTerms.All(rt => agreedTerms.Any(ut => ut.term_id == rt.term_id && ut.term_version == rt.term_version)))
            {
                return false;
            }

            var requiredScopeSet = _dbContext.client_scopes
                .Where(x => x.client_id == clientId && x.status == Code.Status.ACTIVE && x.required)
                .Select(x => x.scope)
                .ToHashSet(StringComparer.Ordinal);
            if (!requiredScopeSet.IsSubsetOf(requestedScopes))
            {
                return false;
            }

            var agreedScopeSet = _dbContext.user_client_scopes
                .Where(x => x.osolab_id == osolabId && x.client_id == clientId && x.status == Code.Status.ACTIVE)
                .Select(x => x.scope)
                .ToHashSet();
            return requiredScopeSet.All(agreedScopeSet.Contains) && requestedScopes.All(agreedScopeSet.Contains);
        }

        /// <summary>         /// Executes BuildAuthorizeUrl.         /// </summary>
        private static string BuildAuthorizeUrl(AuthorizationSession s)
        {
            return "/Authorize"
                + "?response_type=" + Uri.EscapeDataString(s.ResponseType)
                + "&client_id=" + Uri.EscapeDataString(s.ClientId)
                + "&redirect_uri=" + Uri.EscapeDataString(s.RedirectUri)
                + "&state=" + Uri.EscapeDataString(s.State)
                + "&scope=" + Uri.EscapeDataString(s.Scope)
                + "&code_challenge_method=" + Uri.EscapeDataString(s.CodeChallengeMethod)
                + "&code_challenge=" + Uri.EscapeDataString(s.CodeChallenge)
                + "&nonce=" + Uri.EscapeDataString(s.Nonce);
        }
    }
}
