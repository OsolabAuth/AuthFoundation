using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// 利用規約同意を処理します。
    /// </summary>
    [ApiController]
    [Route("terms")]
    public class TermController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IWebHostEnvironment _environment;
        private readonly AuthorizeExecutionService _authorizeExecutionService;

        /// <summary>
        /// TermController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="environment">ホスティング環境</param>
        /// <param name="authorizeExecutionService">認可実行サービス</param>
        public TermController(
            OsolabAuthContext dbContext,
            IWebHostEnvironment environment,
            AuthorizeExecutionService authorizeExecutionService)
        {
            _dbContext = dbContext;
            _environment = environment;
            _authorizeExecutionService = authorizeExecutionService;
        }

        /// <summary>
        /// 同意画面を返します。
        /// </summary>
        /// <returns>同意画面</returns>
        [HttpGet("view")]
        public IActionResult GetTermView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("term.html").Replace("__SESSION_ID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        /// <summary>
        /// 同意対象の規約一覧を返します。
        /// </summary>
        /// <returns>規約一覧</returns>
        [HttpGet]
        public async Task<IActionResult> GetTerms()
        {
            try
            {
                string sessionId = Request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString();
                ValidateUtil.IndispensableParam(sessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(sessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);

                AuthorizationSession session = await GetAuthorizationSessionRequiredAsync(sessionId);

                List<client_term> terms = await _dbContext.client_terms
                    .Where(x => x.client_id == session.ClientId && x.status == Code.Status.ACTIVE)
                    .OrderBy(x => x.term_id)
                    .ToListAsync();

                return Ok(new
                {
                    client_id = session.ClientId,
                    terms = terms.Select(x => new
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

        /// <summary>
        /// 同意結果を保存し、認可処理を再開します。
        /// </summary>
        /// <returns>処理結果</returns>
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

                string? location = await _authorizeExecutionService.TryExecuteFromSessionAsync(
                    input.SessionId,
                    AuthSession.GetCookieSessionId(Request));
                if (string.IsNullOrWhiteSpace(location))
                {
                    throw new ApiException(Code.SCREEN_EXPIRED, Code.SCREEN_EXPIRED.ErrorMessage);
                }

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

        /// <summary>
        /// HTML テンプレートを読み込みます。
        /// </summary>
        /// <param name="fileName">ファイル名</param>
        /// <returns>HTML 文字列</returns>
        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Auth", fileName);
            return System.IO.File.ReadAllText(path);
        }

        /// <summary>
        /// 認可セッションを取得します。
        /// </summary>
        /// <param name="sessionId">認可セッションID</param>
        /// <returns>認可セッション</returns>
        /// <exception cref="ApiException">00006:画面の有効期限切れ</exception>
        private async Task<AuthorizationSession> GetAuthorizationSessionRequiredAsync(string sessionId)
        {
            AuthorizationSession session = await _authorizeExecutionService.LoadAuthorizationSessionAsync(sessionId);
            if (string.IsNullOrWhiteSpace(session.SessionId))
            {
                throw new ApiException(Code.SCREEN_EXPIRED, Code.SCREEN_EXPIRED.ErrorMessage);
            }

            return session;
        }

        /// <summary>
        /// 同意結果を保存します。
        /// </summary>
        /// <param name="session">認可セッション</param>
        /// <param name="acceptedTermIds">同意した規約ID</param>
        /// <exception cref="ApiException">00001:リクエストパラメータエラー</exception>
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

        /// <summary>
        /// 同意入力を表します。
        /// </summary>
        public sealed class Input
        {
            public string SessionId { get; set; } = string.Empty;

            public bool Accepted { get; set; }

            public string AcceptedRaw { get; set; } = string.Empty;

            public List<long> TermIds { get; set; } = new();

            /// <summary>
            /// HTTP リクエストから入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>同意入力</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);

                IFormCollection form = await request.ReadFormAsync();
                List<long> termIds = new List<long>();
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

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(AcceptedRaw, Code.HttpBodies.ACCEPTED.Key);
                ValidateUtil.FormatParam(AcceptedRaw, Code.HttpBodies.ACCEPTED.Key, Code.HttpBodies.ACCEPTED.Regex);
            }
        }

        /// <summary>
        /// エラー応答を表します。
        /// </summary>
        private sealed class ErrorOutput
        {
            public string response_code { get; }

            public string message { get; }

            /// <summary>
            /// エラー応答を初期化します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public ErrorOutput(ApiException ex)
            {
                response_code = ex.Code;
                message = ex.ErrorMessage;
            }
        }
    }
}
