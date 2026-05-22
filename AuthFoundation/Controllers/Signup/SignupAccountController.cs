using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Signup
{
    /// <summary>
    /// サインアップ本登録を処理します。
    /// </summary>
    [ApiController]
    [Route("signup/account")]
    public class SignupAccountController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly AuthorizeExecutionService _authorizeExecutionService;
        private readonly ILogger<SignupAccountController> _logger;

        /// <summary>
        /// SignupAccountController を初期化します。
        /// </summary>
        public SignupAccountController(
            OsolabAuthContext dbContext,
            IRedisClient redis,
            AuthorizeExecutionService authorizeExecutionService,
            ILogger<SignupAccountController> logger)
        {
            _dbContext = dbContext;
            _redis = redis;
            _authorizeExecutionService = authorizeExecutionService;
            _logger = logger;
        }

        /// <summary>
        /// 本登録を作成します。
        /// </summary>
        [HttpPost(Name = "PostSignupAccount")]
        public async Task<IActionResult> PostAccount()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.ValidationCheck();

                SignupSession verify = await GetSignupSessionAsync(input.SignupSessionId);
                if (!verify.Verified)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification is not completed");
                }

                osolab_user user = RegisterOrUpdateUser(verify.Email, input.Password);
                await _redis.DeleteAsync(SignupSession.GetRedisKey(verify.SignupSessionId), Code.RedisDbNo.SIGNUP_SESSION);

                string loginSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
                AuthSession loginSession = new AuthSession(loginSessionId, user.osolab_id, user.email, string.Empty);
                await loginSession.WriteToRedisAsync(_redis);
                loginSession.AppendCookie(Response);

                AuthorizeExecutionService.AuthorizResult? excuteResult = await _authorizeExecutionService.TryExecuteFromSessionAsync(verify.AuthRequestSessionId, loginSessionId);
                if (excuteResult is null || string.IsNullOrWhiteSpace(excuteResult.RedirectUrl))
                {
                    throw new ApiException(Code.SCREEN_EXPIRED, Code.SCREEN_EXPIRED.ErrorDescription);
                }

                Response.Headers.Location = excuteResult.RedirectUrl;
                return Ok(new Output
                {
                    result = "redirect",
                    response_code = Code.SUCCESS.Code,
                    message = Code.SUCCESS.ErrorDescription
                });
            }
            catch (ApiException aex)
            {
                StructuredLog.LogInfo(_logger, "SignupAccount.ApiException", new
                {
                    aex.InternalCode,
                    Status = (int)aex.StatusCode,
                    aex.ErrorDescription
                });
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.StatusCode };
            }
            catch (Exception ex)
            {
                StructuredLog.LogException(_logger, "SignupAccount.UnhandledException", ex);
                return new ObjectResult(new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                {
                    StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        private osolab_user RegisterOrUpdateUser(string email, string password)
        {
            osolab_user? currentUser = _dbContext.osolab_users.FirstOrDefault(x =>
                x.email == email &&
                x.status != Code.Status.INACTIVE);
            if (currentUser is not null && currentUser.status == Code.Status.ACTIVE)
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already in use");
            }

            osolab_user user = currentUser ?? TableHelper.CreateNewOsolabUser(_dbContext, email, password);
            if (currentUser is null)
            {
                _dbContext.Add(user);
            }

            string nonce = Helper.GenerateRandomCode(Code.Nonce.LENGTH, Code.Nonce.CHARACTORS);
            user.nonce = nonce;
            user.password = Helper.GetPassHash(password, nonce);
            user.status = Code.Status.ACTIVE;
            user.update_datetime = DateTime.UtcNow;

            _dbContext.SaveChanges();
            return user;
        }

        private async Task<SignupSession> GetSignupSessionAsync(string signupSessionId)
        {
            SignupSession verify = new SignupSession();
            string? raw = await verify.ReadValueFromRedisAsync(_redis, signupSessionId);
            if (string.IsNullOrWhiteSpace(raw) || !verify.SetValue(raw))
            {
                throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification session is invalid");
            }

            return verify;
        }

        /// <summary>
        /// サインアップ入力を表します。
        /// </summary>
        public sealed class Input
        {
            public string SignupSessionId { get; set; } = string.Empty;

            public string Password { get; set; } = string.Empty;

            /// <summary>
            /// HTTP リクエストから入力を生成します。
            /// </summary>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);
                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    SignupSessionId = GetSignupSessionId(request, form),
                    Password = form["password"].ToString()
                };
            }

            /// <summary>
            /// 入力値を検証します。
            /// </summary>
            public void ValidationCheck()
            {
                ValidateUtil.IndispensableParam(SignupSessionId, "signup_session_id");
                ValidateUtil.FormatParam(SignupSessionId, "signup_session_id", Code.HttpBodies.SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(Password, Code.HttpBodies.PASSWORD.Key);
                ValidateUtil.FormatParam(Password, Code.HttpBodies.PASSWORD.Key, Code.HttpBodies.PASSWORD.Regex);
            }

            private static string GetSignupSessionId(HttpRequest request, IFormCollection form)
            {
                string sessionId = form["signup_session_id"].ToString();
                if (!string.IsNullOrWhiteSpace(sessionId))
                {
                    return sessionId;
                }

                sessionId = request.Headers["x-signup-session-id"].ToString();
                if (!string.IsNullOrWhiteSpace(sessionId))
                {
                    return sessionId;
                }

                return request.Cookies["signup_session_id"] ?? string.Empty;
            }
        }

        /// <summary>
        /// サインアップ応答を表します。
        /// </summary>
        private sealed class Output
        {
            public string? result { get; set; }

            public string? response_code { get; set; }

            public string? message { get; set; }

            public Output()
            {
            }

            public Output(ApiException ex)
            {
                result = "error";
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
            }
        }
    }
}


