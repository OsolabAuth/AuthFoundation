using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

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

                osolab_user user = RegisterOrUpdateUser(verify.Email, input.Password, input.Name, input.Birthdate);
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

        private osolab_user RegisterOrUpdateUser(string email, string password, string name, string birthdate)
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

            UpsertSharedUserInfo(user.osolab_id, "name", name);
            UpsertSharedUserInfo(user.osolab_id, "birthdate", birthdate);

            _dbContext.SaveChanges();
            return user;
        }

        private void UpsertSharedUserInfo(string osolabId, string dataKey, string dataValue)
        {
            user_info? info = _dbContext.user_infos.FirstOrDefault(x =>
                x.osolab_id == osolabId &&
                x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID &&
                x.data_key == dataKey);

            DateTime now = DateTime.UtcNow;
            if (info is null)
            {
                _dbContext.user_infos.Add(new user_info
                {
                    osolab_id = osolabId,
                    client_id = Code.InnerClient.OSOLAB_CLIENT_ID,
                    data_key = dataKey,
                    data_value = dataValue,
                    create_datetime = now,
                    update_datetime = now,
                    status = Code.Status.ACTIVE
                });
                return;
            }

            info.data_value = dataValue;
            info.update_datetime = now;
            info.status = Code.Status.ACTIVE;
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

            public string Name { get; set; } = string.Empty;

            public string Birthdate { get; set; } = string.Empty;

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
                    Password = form["password"].ToString(),
                    Name = form["name"].ToString().Trim(),
                    Birthdate = form["birthdate"].ToString().Trim()
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
                ValidateUtil.IndispensableParam(Name, Code.HttpBodies.NAME.Key);
                ValidateUtil.FormatParam(Name, Code.HttpBodies.NAME.Key, Code.HttpBodies.NAME.Regex);
                ValidateUtil.IndispensableParam(Birthdate, Code.HttpBodies.BIRTHDATE.Key);
                ValidateUtil.FormatParam(Birthdate, Code.HttpBodies.BIRTHDATE.Key, Code.HttpBodies.BIRTHDATE.Regex);
                if (!DateOnly.TryParseExact(Birthdate, "yyyy-MM-dd", out DateOnly parsedBirthdate) ||
                    parsedBirthdate > DateOnly.FromDateTime(DateTime.UtcNow))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "birthdate is invalid");
                }
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

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string? error { get; set; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string? error_code { get; set; }

            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string? error_description { get; set; }

            public Output()
            {
            }

            public Output(ApiException ex)
            {
                result = "error";
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
                error = ex.Error;
                error_code = ex.InternalCode;
                error_description = ex.ErrorDescription;
            }
        }
    }
}


