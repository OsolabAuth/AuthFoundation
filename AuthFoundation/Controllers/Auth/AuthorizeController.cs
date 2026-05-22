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
                // Client検証
                Helper.CertAuthorizeClient(_dbContext, input.ClientId, input.RedirectUri);

                // 認可処理実行
                AuthRequestSession session = input.ToAuthRequestSession();
                AuthorizeExecutionService.AuthorizResult excuteResult = await _authorizeExecutionService.ExecuteAsync(session, AuthSession.GetCookieSessionId(Request));

                // 認可リクエストセッションをCookieに登録
                if (excuteResult.SetSessionCookie && !string.IsNullOrWhiteSpace(excuteResult.SessionId))
                {
                    CookieOptions options = Helper.BuildSessionCookieOptions(Response.HttpContext.Request, Code.AuthCode.EXPIRE_SEC);
                    Response.Cookies.Append(Code.AUTH_REQUEST_SESSION_COOKIE_KEY, excuteResult.SessionId, options);
                }

                SetNoStoreHeaders(Response);
                return Redirect(excuteResult.RedirectUrl);
            }
            catch (ApiException ex)
            {
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(ex))
                {
                    StatusCode = (int)ex.StatusCode
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(apiEx))
                {
                    StatusCode = (int)apiEx.StatusCode
                };
            }
        }

        private static void SetNoStoreHeaders(HttpResponse response)
        {
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["Pragma"] = "no-cache";
        }

        private sealed class ErrorOutput
        {
            public string response_code { get; }
            public string message { get; }
            public string error { get; }
            public string error_description { get; }

            public ErrorOutput(ApiException ex)
            {
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
                error = ToOAuthError(ex);
                error_description = ex.ErrorDescription;
            }

            private static string ToOAuthError(ApiException ex)
            {
                if (string.Equals(ex.InternalCode, Code.ILLEGAL_CLIENT.InternalCode, StringComparison.Ordinal))
                {
                    return "invalid_client";
                }

                if (string.Equals(ex.InternalCode, Code.INVALID_SCOPE.InternalCode, StringComparison.Ordinal))
                {
                    return "invalid_scope";
                }

                if (string.Equals(ex.InternalCode, Code.INTERNAL_SERVER_ERROR.InternalCode, StringComparison.Ordinal))
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

