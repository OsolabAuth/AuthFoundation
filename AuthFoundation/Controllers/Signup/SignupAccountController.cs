using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Signup
{
    /// <summary>
    /// サインアップ仮登録を処理します。
    /// </summary>
    [ApiController]
    [Route("Signup/Account")]
    public class SignupAccountController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;

        /// <summary>
        /// SignupAccountController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="environment">ホスティング環境</param>
        public SignupAccountController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
        }

        /// <summary>
        /// サインアップ画面を返します。
        /// </summary>
        /// <returns>サインアップ画面</returns>
        [HttpGet("view")]
        public IActionResult GetSignupView()
        {
            string sessionId = Request.Query["session_id"].ToString();
            string safeSessionId = System.Net.WebUtility.HtmlEncode(sessionId);
            string html = LoadTemplate("signup-account.html").Replace("__SID__", safeSessionId, StringComparison.Ordinal);
            return Content(html, "text/html; charset=utf-8");
        }

        /// <summary>
        /// 仮登録を作成します。
        /// </summary>
        /// <returns>確認メール用 URL</returns>
        [HttpPost(Name = "PostSignupAccount")]
        public async Task<IActionResult> PostAccount()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.ValidationCheck();

                AuthorizationSession authz = await GetAuthorizationSessionAsync(input.SessionId);
                client_master client = Helper.CertClient(_dbContext, authz.ClientId);
                if (client.status != Code.Status.ACTIVE)
                {
                    throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);
                }

                bool exists = _dbContext.osolab_users.Any(x =>
                    x.email == input.Body.Email
                    && (x.status == Code.Status.TENTATIVE || x.status == Code.Status.ACTIVE));
                if (exists)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already in use");
                }

                osolab_user user = TableHelper.CreateNewOsolabUser(_dbContext, input.Body.Email, input.Body.Password);
                user.status = Code.Status.TENTATIVE;
                _dbContext.Add(user);
                _dbContext.SaveChanges();

                MailVerificationSession verify = new MailVerificationSession
                {
                    VerificationToken = Helper.GenerateRandomCode(48, Code.AuthCode.CHARACTORS),
                    OsolabId = user.osolab_id,
                    Email = user.email,
                    SessionId = input.SessionId
                };
                await verify.CreateSession(_redis);

                string verifyUrl = $"/Signup/Verify?token={Uri.EscapeDataString(verify.VerificationToken)}";
                return Ok(new Output(verifyUrl));
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                return new ObjectResult(new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                {
                    StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        /// <summary>
        /// HTML テンプレートを読み込みます。
        /// </summary>
        /// <param name="fileName">ファイル名</param>
        /// <returns>HTML 文字列</returns>
        private string LoadTemplate(string fileName)
        {
            string path = Path.Combine(_environment.ContentRootPath, "ViewTemplates", "Signup", fileName);
            return System.IO.File.ReadAllText(path);
        }

        /// <summary>
        /// 認可セッションを取得します。
        /// </summary>
        /// <param name="sessionId">認可セッションID</param>
        /// <returns>認可セッション</returns>
        /// <exception cref="ApiException">00001:リクエストパラメータエラー</exception>
        private async Task<AuthorizationSession> GetAuthorizationSessionAsync(string sessionId)
        {
            AuthorizationSession session = new AuthorizationSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, sessionId);
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is not found");
            }

            if (!session.SetValue(raw))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "authorization session is invalid");
            }

            return session;
        }

        /// <summary>
        /// サインアップ入力を表します。
        /// </summary>
        public class Input
        {
            /// <summary>
            /// 認可セッションIDを取得または設定します。
            /// </summary>
            public string SessionId { get; set; } = string.Empty;

            /// <summary>
            /// 入力ボディを取得または設定します。
            /// </summary>
            public JsonBody Body { get; set; } = new JsonBody();

            /// <summary>
            /// 入力ボディを表します。
            /// </summary>
            public class JsonBody
            {
                /// <summary>
                /// メールアドレスを取得または設定します。
                /// </summary>
                public string Email { get; set; } = string.Empty;

                /// <summary>
                /// パスワードを取得または設定します。
                /// </summary>
                public string Password { get; set; } = string.Empty;
            }

            /// <summary>
            /// HTTP リクエストから入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>サインアップ入力</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);
                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    SessionId = request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString(),
                    Body = new JsonBody
                    {
                        Email = form["email"].ToString(),
                        Password = form["password"].ToString()
                    }
                };
            }

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key);
                ValidateUtil.FormatParam(SessionId, Code.HttpHeaders.X_SESSION_ID.Key, Code.HttpHeaders.X_SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(Body.Email, Code.HttpBodies.EMAIL.Key);
                ValidateUtil.FormatParam(Body.Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
                ValidateUtil.IndispensableParam(Body.Password, Code.HttpBodies.PASSWORD.Key);
                ValidateUtil.FormatParam(Body.Password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            }
        }

        /// <summary>
        /// サインアップ応答を表します。
        /// </summary>
        private class Output
        {
            /// <summary>
            /// 応答コードを取得します。
            /// </summary>
            public string StatusCode { get; }

            /// <summary>
            /// メッセージを取得します。
            /// </summary>
            public string Message { get; }

            /// <summary>
            /// 確認 URL を取得します。
            /// </summary>
            public string? VerifyUrl { get; }

            /// <summary>
            /// エラー応答を初期化します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public Output(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }

            /// <summary>
            /// 正常応答を初期化します。
            /// </summary>
            /// <param name="verifyUrl">確認 URL</param>
            public Output(string verifyUrl)
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
                VerifyUrl = verifyUrl;
            }
        }
    }
}
