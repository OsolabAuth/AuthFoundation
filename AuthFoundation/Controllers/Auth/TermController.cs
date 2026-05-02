using System.IO;
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
    [Route("term")]
    public class TermController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;

        public TermController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
        }

        [HttpGet("view", Name = "GetTermView")]
        public IActionResult GetTermView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("term.html").Replace("__SESSION_ID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Auth", fileName);
            return System.IO.File.ReadAllText(path);
        }

        [HttpGet(Name = "GetTerm")]
        public async Task<IActionResult> GetTerm()
        {
            try
            {
                string authSessionId = Request.Query["session_id"].ToString();
                ValidateUtil.IndispensableParam(authSessionId, "session_id");
                ValidateUtil.FormatParam(authSessionId, "session_id", Code.HttpHeaders.X_SESSION_ID.Regex);

                AuthorizationSession session = await GetAuthorizationSessionAsync(authSessionId);
                List<client_term> requiredTerms = await _dbContext.client_terms.Where(x => x.client_id == session.ClientId && x.status == Code.Status.ACTIVE && x.required).OrderBy(x => x.term_id).ToListAsync();
                List<client_scope> requiredScopes = await _dbContext.client_scopes.Where(x => x.client_id == session.ClientId && x.status == Code.Status.ACTIVE && x.required).OrderBy(x => x.scope).ToListAsync();

                return Ok(new { StatusCode = Code.SUCCESS.Code, Message = Code.SUCCESS.ErrorMessage, SessionId = session.SessionId, ClientId = session.ClientId, Scope = session.Scope, RequiredTerms = requiredTerms.Select(x => new { x.term_id, x.term_version, x.term_title, x.term_url }), RequiredScopes = requiredScopes.Select(x => x.scope) });
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }

        [HttpPost(Name = "PostTerm")]
        public async Task<IActionResult> PostTerm()
        {
            try
            {
                string authSessionId = Request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString();
                ValidateUtil.IndispensableParam(authSessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(authSessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);

                AuthorizationSession session = await GetAuthorizationSessionAsync(authSessionId);
                await SaveConsentAsync(session);

                string code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS);
                osolab_user? user = await _dbContext.osolab_users.SingleOrDefaultAsync(x => x.osolab_id == session.OsolabId && x.status == Code.Status.ACTIVE);
                if (user == null) throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);

                AuthCodeSession codeSession = new AuthCodeSession { Code = code, OsolabId = session.OsolabId, Email = user.email, ClientId = session.ClientId, RedirectUri = session.RedirectUri, Scope = session.Scope, CodeChallenge = session.CodeChallenge, CodeChallengeMethod = session.CodeChallengeMethod, Nonce = session.Nonce, State = session.State };
                await codeSession.CreateSession(_redis);

                return Ok(new { StatusCode = Code.SUCCESS.Code, Message = Code.SUCCESS.ErrorMessage, RedirectUri = BuildRedirectUri(session.RedirectUri, code, session.State), Code = code, State = session.State });
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }

        private async Task<AuthorizationSession> GetAuthorizationSessionAsync(string authSessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(authSessionId));
            if (string.IsNullOrWhiteSpace(raw)) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is not found");
            AuthorizationSession? session = JsonConvert.DeserializeObject<AuthorizationSession>(raw);
            if (session == null) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
            return session;
        }

        private async Task SaveConsentAsync(AuthorizationSession session)
        {
            if (string.IsNullOrWhiteSpace(session.OsolabId)) throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "login session is required");
            DateTime now = DateTime.UtcNow;

            List<client_term> requiredTerms = await _dbContext.client_terms.Where(x => x.client_id == session.ClientId && x.status == Code.Status.ACTIVE && x.required).ToListAsync();
            foreach (client_term term in requiredTerms)
            {
                bool exists = await _dbContext.user_terms.AnyAsync(x => x.osolab_id == session.OsolabId && x.client_id == session.ClientId && x.term_id == term.term_id && x.term_version == term.term_version && x.status == Code.Status.ACTIVE);
                if (!exists)
                {
                    _dbContext.user_terms.Add(new user_term { osolab_id = session.OsolabId, client_id = session.ClientId, term_id = term.term_id, term_version = term.term_version, agreed_at = now, create_datetime = now, update_datetime = now, status = Code.Status.ACTIVE });
                }
            }

            string[] requestedScopes = session.Scope.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToArray();
            foreach (string scope in requestedScopes)
            {
                bool exists = await _dbContext.user_client_scopes.AnyAsync(x => x.osolab_id == session.OsolabId && x.client_id == session.ClientId && x.scope == scope && x.status == Code.Status.ACTIVE);
                if (!exists)
                {
                    _dbContext.user_client_scopes.Add(new user_client_scope { osolab_id = session.OsolabId, client_id = session.ClientId, scope = scope, agreed_at = now, create_datetime = now, update_datetime = now, status = Code.Status.ACTIVE });
                }
            }

            await _dbContext.SaveChangesAsync();
        }

        private static string BuildRedirectUri(string redirectUri, string code, string state)
        {
            string separator = redirectUri.Contains('?') ? "&" : "?";
            return $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        }
    }
}
