using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Signup
{
    /// <summary>
    /// サインアップ用メール送信を処理します。
    /// </summary>
    [ApiController]
    [Route("signup/email")]
    public class SignupEmailController : ControllerBase
    {
        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;
        private readonly GmailSmtpMail _gmailSmtpMail;
        private readonly ILogger<SignupEmailController> _logger;

        /// <summary>
        /// SignupEmailController を初期化します。
        /// </summary>
        public SignupEmailController(
            OsolabAuthContext dbContext,
            IRedisClient redis,
            GmailSmtpMail gmailSmtpMail,
            ILogger<SignupEmailController> logger)
        {
            _dbContext = dbContext;
            _redis = redis;
            _gmailSmtpMail = gmailSmtpMail;
            _logger = logger;
        }

        /// <summary>
        /// 認証コード送信を実行します。
        /// </summary>
        [HttpPost]
        public async Task<IActionResult> PostEmail()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                AuthRequestSession authz = await GetAuthRequestSessionAsync(input.AuthRequestSessionId);
                Helper.CertClient(_dbContext, authz.ClientId);

                osolab_user? currentUser = _dbContext.osolab_users.FirstOrDefault(x =>
                    x.email == input.Email &&
                    x.status != Code.Status.INACTIVE);
                if (currentUser is not null && currentUser.status == Code.Status.ACTIVE)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "email is already in use");
                }

                string signupSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
                string code = await Helper.SendMailAsync(_gmailSmtpMail, input.Email);
                SignupSession verify = new SignupSession
                {
                    SignupSessionId = signupSessionId,
                    AuthRequestSessionId = input.AuthRequestSessionId,
                    Email = input.Email,
                    Code = code,
                    Verified = false
                };
                await verify.CreateSession(_redis);

                AppendSignupSessionCookie(Response, signupSessionId);
                return Ok(new Output());
            }
            catch (ApiException aex)
            {
                StructuredLog.LogInfo(_logger, "SignupEmail.ApiException", new
                {
                    aex.Code,
                    Status = (int)aex.Status,
                    aex.ErrorMessage
                });
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                StructuredLog.LogException(_logger, "SignupEmail.UnhandledException", ex);
                return new ObjectResult(new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                {
                    StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        private static void AppendSignupSessionCookie(HttpResponse response, string signupSessionId)
        {
            response.Cookies.Append("signup_session_id", signupSessionId, new CookieOptions
            {
                HttpOnly = true,
                Secure = response.HttpContext.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                MaxAge = TimeSpan.FromSeconds(SignupSession.ExpireSeconds)
            });
        }

        private async Task<AuthRequestSession> GetAuthRequestSessionAsync(string sessionId)
        {
            AuthRequestSession session = new AuthRequestSession();
            string? raw = await session.ReadValueFromRedisAsync(_redis, sessionId);
            if (string.IsNullOrWhiteSpace(raw) || !session.SetValue(raw))
            {
                throw new ApiException(Code.SCREEN_EXPIRED, Code.SCREEN_EXPIRED.ErrorMessage);
            }

            return session;
        }

        public sealed class Input
        {
            public string AuthRequestSessionId { get; set; } = string.Empty;

            public string Email { get; set; } = string.Empty;

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);
                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    AuthRequestSessionId = Helper.GetSessionId(request, form),
                    Email = form["email"].ToString()
                };
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(AuthRequestSessionId, Code.HttpBodies.SESSION_ID.Key);
                ValidateUtil.FormatParam(AuthRequestSessionId, Code.HttpBodies.SESSION_ID.Key, Code.HttpBodies.SESSION_ID.Regex);
                ValidateUtil.IndispensableParam(Email, Code.HttpBodies.EMAIL.Key);
                ValidateUtil.FormatParam(Email, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            }
        }

        private sealed class Output
        {
            public string StatusCode { get; }

            public string Message { get; }

            public Output()
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorMessage;
            }

            public Output(ApiException ex)
            {
                StatusCode = ex.Code;
                Message = ex.ErrorMessage;
            }
        }
    }
}


