using AuthFoundation.Common;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Signup
{
    /// <summary>
    /// サインアップ認証コードの再送を処理します。
    /// </summary>
    [ApiController]
    [Route("signup/resend")]
    public class SignupResendController : ControllerBase
    {
        private readonly IRedisClient _redis;
        private readonly GmailSmtpMail _gmailSmtpMail;

        /// <summary>
        /// SignupResendController を初期化します。
        /// </summary>
        public SignupResendController(IRedisClient redis, GmailSmtpMail gmailSmtpMail)
        {
            _redis = redis;
            _gmailSmtpMail = gmailSmtpMail;
        }

        /// <summary>
        /// 認証コードを再送します。
        /// </summary>
        [HttpPost]
        public async Task<IActionResult> Resend()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                input.Validate();

                SignupSession verify = new SignupSession();
                string? raw = await verify.ReadValueFromRedisAsync(_redis, input.SignupSessionId);
                if (string.IsNullOrWhiteSpace(raw) || !verify.SetValue(raw))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "verification session is invalid");
                }

                verify.Code = await Helper.SendMailAsync(_gmailSmtpMail, verify.Email);
                verify.Verified = false;
                await verify.WriteToRedisAsync(_redis);

                return Ok(new Output());
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new Output(aex)) { StatusCode = (int)aex.StatusCode };
            }
            catch (Exception ex)
            {
                return new ObjectResult(new Output(new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message)))
                {
                    StatusCode = (int)Code.INTERNAL_SERVER_ERROR.Status
                };
            }
        }

        public sealed class Input
        {
            public string SignupSessionId { get; set; } = string.Empty;

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);
                IFormCollection form = await request.ReadFormAsync();
                return new Input
                {
                    SignupSessionId = GetSignupSessionId(request, form)
                };
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(SignupSessionId, "signup_session_id");
                ValidateUtil.FormatParam(SignupSessionId, "signup_session_id", Code.HttpBodies.SESSION_ID.Regex);
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

        private sealed class Output
        {
            public string StatusCode { get; }

            public string Message { get; }

            public Output()
            {
                StatusCode = Code.SUCCESS.Code;
                Message = Code.SUCCESS.ErrorDescription;
            }

            public Output(ApiException ex)
            {
                StatusCode = ex.InternalCode;
                Message = ex.ErrorDescription;
            }
        }
    }
}


