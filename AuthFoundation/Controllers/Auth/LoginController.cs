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

                string inputPassHash = Helper.GetPassHash(input.Password, user.nonce);
                if (!Helper.IsSameValue(user.password, inputPassHash))
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
        /// ログイン状態を返します。
        /// </summary>
        /// <returns>ログイン状態</returns>
        [HttpGet("status")]
        public async Task<IActionResult> GetStatus()
        {
            try
            {
                string? loginSessionId = AuthSession.GetCookieSessionId(Request);
                if (string.IsNullOrWhiteSpace(loginSessionId))
                {
                    return Ok(new
                    {
                        response_code = Code.SUCCESS.Code,
                        logged_in = false
                    });
                }

                AuthSession session = new AuthSession();
                string? raw = await session.ReadValueFromRedisAsync(_redis, loginSessionId);
                bool loggedIn = !string.IsNullOrWhiteSpace(raw) && session.SetValue(raw);

                return Ok(new
                {
                    response_code = Code.SUCCESS.Code,
                    logged_in = loggedIn
                });
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new
                {
                    response_code = ex.Code,
                    message = ex.ErrorMessage
                })
                {
                    StatusCode = (int)ex.Status
                };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new
                {
                    response_code = apiEx.Code,
                    message = apiEx.ErrorMessage
                })
                {
                    StatusCode = (int)apiEx.Status
                };
            }
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
                    SessionId = Helper.GetSessionId(request, form),
                    Email = form["email"].ToString(),
                    Password = form["password"].ToString()
                };
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
                ValidateUtil.FormatParam(Password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
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
