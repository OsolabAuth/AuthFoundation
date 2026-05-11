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

                Helper.CertClient(_dbContext, input.ClientId);
                if (!Helper.IsRedirectUriFormatValid(input.RedirectUri))
                {
                    throw new ApiException(Code.ILLEGAL_REDIRECT_URI, Code.ILLEGAL_REDIRECT_URI.ErrorMessage);
                }

                AuthorizationSession session = input.ToAuthorizationSession();
                string location = await _authorizeExecutionService.ExecuteAsync(session, AuthSession.GetCookieSessionId(Request));
                return Redirect(location);
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

        /// <summary>
        /// 認可入力を表します。
        /// </summary>
        public sealed class Input
        {
            /// <summary>
            /// ResponseType を取得または設定します。
            /// </summary>
            public string ResponseType { get; set; } = string.Empty;

            /// <summary>
            /// ClientId を取得または設定します。
            /// </summary>
            public string ClientId { get; set; } = string.Empty;

            /// <summary>
            /// RedirectUri を取得または設定します。
            /// </summary>
            public string RedirectUri { get; set; } = string.Empty;

            /// <summary>
            /// State を取得または設定します。
            /// </summary>
            public string State { get; set; } = string.Empty;

            /// <summary>
            /// Scope を取得または設定します。
            /// </summary>
            public string Scope { get; set; } = string.Empty;

            /// <summary>
            /// CodeChallengeMethod を取得または設定します。
            /// </summary>
            public string CodeChallengeMethod { get; set; } = string.Empty;

            /// <summary>
            /// CodeChallenge を取得または設定します。
            /// </summary>
            public string CodeChallenge { get; set; } = string.Empty;

            /// <summary>
            /// Nonce を取得または設定します。
            /// </summary>
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
            public AuthorizationSession ToAuthorizationSession()
            {
                return new AuthorizationSession
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
