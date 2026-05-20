using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// ログイン処理を提供します。
    /// </summary>
    [ApiController]
    [Route("login")]
    public class LoginController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly IWebHostEnvironment _environment;
        private readonly AuthorizeExecutionService _authorizeExecutionService;

        /// <summary>
        /// LoginController を初期化します。
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="environment">ホスティング環境</param>
        /// <param name="authorizeExecutionService">認可実行サービス</param>
        public LoginController(
            OsolabAuthContext dbContext,
            IRedisClient redis,
            IWebHostEnvironment environment,
            AuthorizeExecutionService authorizeExecutionService)
        {
            _dbContext = dbContext;
            _redis = redis;
            _environment = environment;
            _authorizeExecutionService = authorizeExecutionService;
        }

        /// <summary>
        /// ログインを実行します。
        /// </summary>
        /// <returns>ログイン結果</returns>
        [HttpPost]
        public async Task<IActionResult> PostLogin()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                osolab_user? user = _dbContext.osolab_users.SingleOrDefault(x =>
                    x.email == input.Email && x.status == Code.Status.ACTIVE);
                if (user == null)
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                string passwordHashHex = NormalizePasswordHash(input.Password);
                string inputPassHash = Helper.GetPassHash(passwordHashHex, user.nonce);
                if (!IsSameValue(user.password, inputPassHash))
                {
                    throw new ApiException(Code.AUTHENTICATION_FAILED, Code.AUTHENTICATION_FAILED.ErrorMessage);
                }

                string loginSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
                AuthSession loginSession = new AuthSession(loginSessionId, user.osolab_id, user.email, string.Empty);
                await loginSession.WriteToRedisAsync(_redis);
                loginSession.AppendCookie(Response);

                if (string.IsNullOrWhiteSpace(input.SessionId))
                {
                    return Ok(new Output
                    {
                        result = "logged_in",
                        response_code = "00006",
                        message = "Logged in, but authorization session is missing or expired."
                    });
                }

                string? location = await _authorizeExecutionService.TryExecuteFromSessionAsync(input.SessionId, loginSessionId);
                if (string.IsNullOrWhiteSpace(location))
                {
                    return Ok(new Output
                    {
                        result = "logged_in",
                        response_code = "00006",
                        message = "Logged in, but authorization session is missing or expired."
                    });
                }

                Response.Headers.Location = location;
                return Ok(new Output
                {
                    result = "redirect",
                    response_code = Code.SUCCESS.Code,
                    message = Code.SUCCESS.ErrorMessage
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new Output(ex)) { StatusCode = (int)ex.Status };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new Output(apiEx)) { StatusCode = (int)apiEx.Status };
            }
        }

        /// <summary>
        /// パスワード入力値をハッシュ文字列へ正規化します。
        /// </summary>
        /// <param name="passwordInput">入力値</param>
        /// <returns>SHA-256 ハッシュ文字列</returns>
        private static string NormalizePasswordHash(string passwordInput)
        {
            if (Regex.IsMatch(passwordInput, Code.HttpBodies.PASSWORD.Regex))
            {
                return passwordInput.ToUpperInvariant();
            }

            byte[] plainBytes = Encoding.UTF8.GetBytes(passwordInput);
            byte[] sha = SHA256.HashData(plainBytes);
            return Convert.ToHexString(sha);
        }

        /// <summary>
        /// 文字列を固定時間比較します。
        /// </summary>
        /// <param name="expected">期待値</param>
        /// <param name="actual">比較値</param>
        /// <returns>一致する場合は true</returns>
        private static bool IsSameValue(string expected, string actual)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actual);
            return expectedBytes.Length == actualBytes.Length
                && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        /// <summary>
        /// ログイン入力を表します。
        /// </summary>
        public sealed class Input
        {
            public string SessionId { get; set; } = string.Empty;

            public string Email { get; set; } = string.Empty;

            public string Password { get; set; } = string.Empty;

            /// <summary>
            /// HTTP リクエストから入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>ログイン入力</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);

                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    SessionId = GetSessionId(request, form),
                    Email = form["email"].ToString(),
                    Password = form["password"].ToString()
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
            public void Validate()
            {
                if (!string.IsNullOrWhiteSpace(SessionId))
                {
                    ValidateUtil.FormatParam(SessionId, Code.HttpBodies.SESSION_ID.Key, Code.HttpBodies.SESSION_ID.Regex);
                }

                ValidateUtil.IndispensableParam(Email, Code.HttpBodies.EMAIL.Key);
                ValidateUtil.FormatParam(Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
                ValidateUtil.IndispensableParam(Password, Code.HttpBodies.PASSWORD.Key);
                if (!Regex.IsMatch(Password, Code.HttpBodies.PASSWORD.Regex))
                {
                    ValidateUtil.FormatParam(Password, Code.HttpBodies.PASSWORD.Key, @"^.{1,256}$");
                }
            }
        }

        /// <summary>
        /// ログイン応答を表します。
        /// </summary>
        private sealed class Output
        {
            public string? result { get; set; }

            public string? response_code { get; set; }

            public string? message { get; set; }

            /// <summary>
            /// 空の応答を初期化します。
            /// </summary>
            public Output()
            {
            }

            /// <summary>
            /// 例外から応答を初期化します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public Output(ApiException ex)
            {
                result = "error";
                response_code = ex.Code;
                message = ex.ErrorMessage;
            }
        }
    }
}
