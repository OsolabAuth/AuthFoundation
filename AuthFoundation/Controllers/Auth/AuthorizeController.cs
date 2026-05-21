using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// 認可処理を提供します。
    /// </summary>
    [ApiController]
    [Route("authorize")]
    public class AuthorizeController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly AuthorizeExecutionService _authorizeExecutionService;

        /// <summary>
        /// AuthorizeController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="authorizeExecutionService">認可実行サービス</param>
        public AuthorizeController(OsolabAuthContext dbContext, AuthorizeExecutionService authorizeExecutionService)
        {
            _dbContext = dbContext;
            _authorizeExecutionService = authorizeExecutionService;
        }

        /// <summary>
        /// 認可処理を実行します。
        /// </summary>
        /// <returns>認可結果</returns>
        [HttpGet]
        public async Task<IActionResult> GetAuthorize()
        {
            try
            {
                Input input = Input.Create(Request.HttpContext);
                input.Validate();

                Helper.CertAuthorizeClient(_dbContext, input.ClientId, input.RedirectUri);

                AuthRequestSession session = input.ToAuthRequestSession();
                string location = await _authorizeExecutionService.ExecuteAsync(session, AuthSession.GetCookieSessionId(Request));
                AppendAuthRequestSessionCookieIfPresent(Response, location);
                if (ShouldReturnBodySession(Request))
                {
                    SetNoStoreHeaders(Response);
                    return Ok(new
                    {
                        result = "redirect",
                        redirect_url = RemoveSessionIdFromUrl(location),
                        session_id = ExtractSessionId(location),
                        response_code = Code.SUCCESS.Code,
                        message = Code.SUCCESS.ErrorMessage
                    });
                }

                SetNoStoreHeaders(Response);
                return Redirect(location);
            }
            catch (ApiException ex)
            {
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.Status
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.Status
                };
            }
        }

        private static void SetNoStoreHeaders(HttpResponse response)
        {
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["Pragma"] = "no-cache";
        }

        private static bool ShouldReturnBodySession(HttpRequest request)
        {
            return string.Equals(
                request.Headers["x-auth-ui-session-mode"].ToString(),
                "body",
                StringComparison.OrdinalIgnoreCase);
        }

        private static void AppendAuthRequestSessionCookieIfPresent(HttpResponse response, string location)
        {
            string sessionId = ExtractSessionId(location);
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return;
            }

            CookieOptions options = Helper.BuildSessionCookieOptions(response.HttpContext.Request, Code.AuthCode.EXPIRE_SEC);

            response.Cookies.Append(Code.AUTH_REQUEST_SESSION_COOKIE_KEY, sessionId, options);
            response.Cookies.Append("session_id", sessionId, options);
        }

        private static string ExtractSessionId(string location)
        {
            string query = GetQuery(location);
            foreach (string part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] pair = part.Split('=', 2);
                if (pair.Length == 2 && string.Equals(pair[0], "session_id", StringComparison.OrdinalIgnoreCase))
                {
                    return Uri.UnescapeDataString(pair[1]);
                }
            }

            return string.Empty;
        }

        private static string RemoveSessionIdFromUrl(string location)
        {
            int questionIndex = location.IndexOf('?', StringComparison.Ordinal);
            if (questionIndex < 0)
            {
                return location;
            }

            string basePart = location[..questionIndex];
            string queryPart = location[(questionIndex + 1)..];
            string filteredQuery = string.Join("&", queryPart
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Where(part => !part.StartsWith("session_id=", StringComparison.OrdinalIgnoreCase)));

            return string.IsNullOrWhiteSpace(filteredQuery)
                ? basePart
                : $"{basePart}?{filteredQuery}";
        }

        private static string GetQuery(string location)
        {
            int questionIndex = location.IndexOf('?', StringComparison.Ordinal);
            if (questionIndex < 0 || questionIndex == location.Length - 1)
            {
                return string.Empty;
            }

            return location[(questionIndex + 1)..];
        }

        private sealed class ErrorOutput
        {
            public string response_code { get; }
            public string message { get; }
            public string error { get; }
            public string error_description { get; }

            public ErrorOutput(ApiException ex)
            {
                response_code = ex.Code;
                message = ex.ErrorMessage;
                error = ToOAuthError(ex);
                error_description = ex.ErrorMessage;
            }

            private static string ToOAuthError(ApiException ex)
            {
                if (string.Equals(ex.Code, Code.ILLEGAL_CLIENT.Code, StringComparison.Ordinal))
                {
                    return "invalid_client";
                }

                if (string.Equals(ex.Code, Code.INVALID_SCOPE.Code, StringComparison.Ordinal))
                {
                    return "invalid_scope";
                }

                if (string.Equals(ex.Code, Code.INTERNAL_SERVER_ERROR.Code, StringComparison.Ordinal))
                {
                    return "server_error";
                }

                return "invalid_request";
            }
        }

        /// <summary>
        /// 認可入力を表します。
        /// </summary>
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

            /// <summary>
            /// HTTP リクエストから認可入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>認可入力</returns>
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

            /// <summary>
            /// 認可セッションへ変換します。
            /// </summary>
            /// <returns>認可セッション</returns>
            public AuthRequestSession ToAuthRequestSession()
            {
                return new AuthRequestSession
                {
                    ResponseType = ResponseType,
                    ClientId = ClientId,
                    RedirectUri = RedirectUri,
                    State = State,
                    Scope = Scope,
                    CodeChallengeMethod = CodeChallengeMethod,
                    CodeChallenge = CodeChallenge,
                    Nonce = Nonce
                };
            }

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void Validate()
            {
                ValidateUtil.IndispensableParam(ResponseType, Code.HttpQueries.RESPONSE_TYPE.Key);
                ValidateUtil.FormatParam(ResponseType, Code.HttpQueries.RESPONSE_TYPE.Key, Code.HttpQueries.RESPONSE_TYPE.Regex);
                ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
                ValidateUtil.IndispensableParam(RedirectUri, Code.HttpQueries.REDIRECT_URI.Key);
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

