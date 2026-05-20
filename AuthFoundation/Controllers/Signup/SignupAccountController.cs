using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using System.Net.Mail;
using System.Text.RegularExpressions;

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
        private readonly BrevoMail _brevoMail;

        /// <summary>
        /// SignupAccountController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="environment">ホスティング環境</param>
        /// <param name="brevoMail">メールクライアント</param>
        public SignupAccountController(OsolabAuthContext dbContext, IRedisClient redis, IWebHostEnvironment environment, BrevoMail brevoMail)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
            _brevoMail = brevoMail;
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

                osolab_user user;
                osolab_user? currentUser = _dbContext.osolab_users.FirstOrDefault(x =>
                    x.email == input.Body.Email &&
                    x.status != Code.Status.INACTIVE);
                if (currentUser is not null && currentUser.status == Code.Status.ACTIVE)
                {
                    // 有効な正規メンバーが存在する場合エラー
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already in use");
                }

                if (currentUser is not null && currentUser.status == Code.Status.TENTATIVE)
                {
                    // 有効な仮メンバーが存在する場合は、パスワードの一致を確認、不一致の場合エラー
                    string inputPassHash = Helper.GetPassHash(input.Body.Password, currentUser.nonce);
                    if (!Helper.IsSameValue(currentUser.password, inputPassHash))
                    {
                        throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already in use");
                    }
                    user = currentUser;
                }
                else
                {
                    // 有効なメンバーが存在しない場合は、新規で仮会員登録
                    user = TableHelper.CreateNewOsolabUser(_dbContext, input.Body.Email, input.Body.Password);
                    user.status = Code.Status.TENTATIVE;
                    _dbContext.Add(user);
                    _dbContext.SaveChanges();
                }
                string code = await Helper.SendMailAsync(_brevoMail, user.email);

                MailVerificationSession verify = new MailVerificationSession
                {
                    VerificationToken = Helper.GenerateRandomCode(48, Code.AuthCode.CHARACTORS),
                    OsolabId = user.osolab_id,
                    Email = user.email,
                    Code = code,
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
            public string SessionId { get; set; } = string.Empty;

            public JsonBody Body { get; set; } = new JsonBody();

            /// <summary>
            /// 入力ボディを表します。
            /// </summary>
            public class JsonBody
            {
                public string Email { get; set; } = string.Empty;

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
                    SessionId = GetSessionId(request, form),
                    Body = new JsonBody
                    {
                        Email = form["email"].ToString(),
                        Password = form["password"].ToString()
                    }
                };
            }

            private static string GetSessionId(HttpRequest request, IFormCollection form)
            {
                string bodySessionId = form["session_id"].ToString();
                return string.IsNullOrWhiteSpace(bodySessionId)
                    ? request.Headers[Code.HttpHeaders.X_SESSION_ID.Key].ToString()
                    : bodySessionId;
            }

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(SessionId, Code.HttpBodies.SESSION_ID.Key);
                ValidateUtil.FormatParam(SessionId, Code.HttpBodies.SESSION_ID.Key, Code.HttpBodies.SESSION_ID.Regex);
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
            public string StatusCode { get; }

            public string Message { get; }

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