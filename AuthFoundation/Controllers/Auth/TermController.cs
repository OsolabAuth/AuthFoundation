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
    [Route("terms")]
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

        [HttpGet("view")]
        public IActionResult GetTermView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("term.html").Replace("__SESSION_ID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        [HttpGet]
        public async Task<IActionResult> GetTerms()
        {
            try
            {
                string sessionId = Request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString();
                ValidateUtil.IndispensableParam(sessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(sessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);

                AuthorizationSession session = await GetAuthorizationSessionRequiredAsync(sessionId);

                List<client_term> requiredTerms = await _dbContext.client_terms
                    .Where(x => x.client_id == session.ClientId && x.status == Code.Status.ACTIVE)
                    .OrderBy(x => x.term_id)
                    .ToListAsync();

                return Ok(new
                {
                    client_id = session.ClientId,
                    terms = requiredTerms.Select(x => new
                    {
                        term_id = x.term_id,
                        title = x.term_title,
                        version = x.term_version,
                        required = x.required
                    }),
                    scopes = Helper.ParseScopes(session.Scope)
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.Status };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx)) { StatusCode = (int)apiEx.Status };
            }
        }

        [HttpPost]
        public async Task<IActionResult> PostTerms()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                AuthorizationSession session = await GetAuthorizationSessionRequiredAsync(input.SessionId);
                if (!input.Accepted)
                {
                    string denyLocation = Helper.BuildRedirectUri(session.RedirectUri, new Dictionary<string, string>
                    {
                        ["error"] = "access_denied",
                        ["state"] = session.State
                    });
                    Response.Headers.Location = denyLocation;
                    return Ok(new { result = "redirect", error = "access_denied" });
                }

                await SaveConsentAsync(session, input.TermIds);

                osolab_user? user = await _dbContext.osolab_users.AsNoTracking()
                    .SingleOrDefaultAsync(x => x.osolab_id == session.OsolabId && x.status == Code.Status.ACTIVE);
                if (user == null)
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                AuthCodeSession codeSession = new AuthCodeSession
                {
                    Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
                    OsolabId = session.OsolabId,
                    Email = user.email,
                    ClientId = session.ClientId,
                    RedirectUri = session.RedirectUri,
                    Scope = session.Scope,
                    CodeChallenge = session.CodeChallenge,
                    CodeChallengeMethod = session.CodeChallengeMethod,
                    Nonce = session.Nonce,
                    State = session.State
                };
                await codeSession.CreateSession(_redis);

                string location = Helper.BuildRedirectUri(session.RedirectUri, new Dictionary<string, string>
                {
                    ["code"] = codeSession.Code,
                    ["state"] = session.State
                });
                Response.Headers.Location = location;

                return Ok(new { result = "redirect" });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.Status };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx)) { StatusCode = (int)apiEx.Status };
            }
        }

        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Auth", fileName);
            return System.IO.File.ReadAllText(path);
        }

        private async Task<AuthorizationSession> GetAuthorizationSessionRequiredAsync(string sessionId)
        {
            string? raw = await _redis.GetStringAsync(AuthorizationSession.GetRedisKey(sessionId));
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new ApiException(Code.SCREEN_EXPIRED, Code.SCREEN_EXPIRED.ErrorMessage);
            }

            AuthorizationSession? session = JsonConvert.DeserializeObject<AuthorizationSession>(raw);
            if (session == null)
            {
                throw new ApiException(Code.SCREEN_EXPIRED, Code.SCREEN_EXPIRED.ErrorMessage);
            }

            return session;
        }

        private async Task SaveConsentAsync(AuthorizationSession session, IReadOnlyCollection<long> acceptedTermIds)
        {
            if (string.IsNullOrWhiteSpace(session.OsolabId))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorMessage);
            }

            List<client_term> requiredTerms = await _dbContext.client_terms
                .Where(x => x.client_id == session.ClientId && x.status == Code.Status.ACTIVE && x.required)
                .ToListAsync();

            HashSet<long> acceptedSet = acceptedTermIds.ToHashSet();
            if (requiredTerms.Any(x => !acceptedSet.Contains(x.term_id)))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorMessage);
            }

            DateTime now = DateTime.UtcNow;
            foreach (client_term term in requiredTerms)
            {
                bool exists = await _dbContext.user_terms.AnyAsync(x =>
                    x.osolab_id == session.OsolabId
                    && x.client_id == session.ClientId
                    && x.term_id == term.term_id
                    && x.term_version == term.term_version
                    && x.status == Code.Status.ACTIVE);

                if (!exists)
                {
                    _dbContext.user_terms.Add(new user_term
                    {
                        osolab_id = session.OsolabId,
                        client_id = session.ClientId,
                        term_id = term.term_id,
                        term_version = term.term_version,
                        agreed_at = now,
                        create_datetime = now,
                        update_datetime = now,
                        status = Code.Status.ACTIVE
                    });
                }
            }

            foreach (string scope in Helper.ParseScopes(session.Scope))
            {
                bool exists = await _dbContext.user_client_scopes.AnyAsync(x =>
                    x.osolab_id == session.OsolabId
                    && x.client_id == session.ClientId
                    && x.scope == scope
                    && x.status == Code.Status.ACTIVE);

                if (!exists)
                {
                    _dbContext.user_client_scopes.Add(new user_client_scope
                    {
                        osolab_id = session.OsolabId,
                        client_id = session.ClientId,
                        scope = scope,
                        agreed_at = now,
                        create_datetime = now,
                        update_datetime = now,
                        status = Code.Status.ACTIVE
                    });
                }
            }

            await _dbContext.SaveChangesAsync();
        }

        public sealed class Input
        {
            public string SessionId { get; set; } = string.Empty;
            public bool Accepted { get; set; }
            public string AcceptedRaw { get; set; } = string.Empty;
            public List<long> TermIds { get; set; } = new();

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);

                IFormCollection form = await request.ReadFormAsync();
                List<long> termIds = new();
                foreach (string? value in form["term_ids"])
                {
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        continue;
                    }

                    if (long.TryParse(value, out long termId))
                    {
                        termIds.Add(termId);
                    }
                }

                return new Input
                {
                    SessionId = request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString(),
                    AcceptedRaw = form["accepted"].ToString(),
                    Accepted = string.Equals(form["accepted"].ToString(), "true", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(form["accepted"].ToString(), "on", StringComparison.OrdinalIgnoreCase),
                    TermIds = termIds
                };
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(AcceptedRaw, Code.HttpBodies.ACCEPTED.Key);
                ValidateUtil.FormatParam(AcceptedRaw, Code.HttpBodies.ACCEPTED.Key, Code.HttpBodies.ACCEPTED.Regex);
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
